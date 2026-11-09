import { IPluginMiddleware, IPluginStorageFilter, PluginOptions, IBasicAuth, IStorageManager, Package, Version } from '@verdaccio/types';
import * as semver from 'semver';
import { readFileSync } from 'fs';
import { join } from 'path';
import { Application, Request, Response, NextFunction } from 'express';

import { SecurityConfig, SecurityRules, VersionRangeRule } from './types';
import { SecurityLogger } from './lib/logger';
import { MetricsCollector } from './lib/metrics';
import { WhitelistChecker } from './lib/whitelist-checker';
import { CVEChecker } from './lib/cve-checker';
import { LicenseChecker } from './lib/license-checker';
import { PackageAgeChecker } from './lib/package-age-checker';
import { AuthorChecker } from './lib/author-checker';

// package.json sits next to both src/ and build/, and is always part of the published package.
const PLUGIN_VERSION: string = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8')).version;

/**
 * Security Filter Plugin for Verdaccio
 * Works with both middleware and filter interfaces for complete protection
 * Compatible with Verdaccio 6.x and 7.x
 *
 * Two-layer protection:
 * - Layer 1 (filter_metadata): CVE/License/Age checks when metadata is available
 * - Layer 2 (middleware): Whitelist/Pattern/Scope checks + tarball blocking
 */
export default class SecurityFilterPlugin implements IPluginMiddleware<SecurityConfig>, IPluginStorageFilter<SecurityConfig> {
    public logger: SecurityLogger;
    public config: SecurityConfig;
    private readonly securityRules: SecurityRules;
    private readonly blockedPatternRegexes: RegExp[];
    private readonly metrics: MetricsCollector;
    private readonly whitelistChecker: WhitelistChecker;
    private readonly cveChecker: CVEChecker;
    private readonly licenseChecker: LicenseChecker;
    private readonly packageAgeChecker: PackageAgeChecker;
    private readonly authorChecker: AuthorChecker;

    /**
     * Creates a new SecurityFilterPlugin instance
     * @param {SecurityConfig} config - Plugin configuration
     * @param {PluginOptions} options - Verdaccio plugin options
     */
    constructor(config: SecurityConfig, options: PluginOptions<SecurityConfig>) {
        this.config = config || {} as SecurityConfig;

        // Set default error handling strategy if not provided
        if (!this.config.errorHandling) {
            this.config.errorHandling = {
                onFilterError: 'fail-open',
                onCveCheckError: 'fail-open',
            };
        }

        // Initialize enhanced logger
        this.logger = new SecurityLogger(options.logger, this.config.logger);

        // Initialize metrics collector
        this.metrics = new MetricsCollector(this.config.metrics);

        // Initialize whitelist checker
        this.whitelistChecker = new WhitelistChecker(this.config.whitelist);

        // Initialize security checkers
        this.cveChecker = new CVEChecker(this.config.cveCheck);
        this.licenseChecker = new LicenseChecker(this.config.licenses);
        this.packageAgeChecker = new PackageAgeChecker(this.config.packageAge);
        this.authorChecker = new AuthorChecker(this.config.authorFilter);

        // Security rules configuration
        this.securityRules = {
            blockedVersions: this.config.blockedVersions || [],
            blockedPatterns: this.config.blockedPatterns || [],
            allowedScopes: this.config.allowedScopes || [],
            blockedScopes: this.config.blockedScopes || [],
            versionRangeRules: this._parseVersionRangeRules(this.config.versionRangeRules || [])
        };

        // Compiled once: the patterns run on every request, and a bad one must not turn into a 500.
        this.blockedPatternRegexes = this.securityRules.blockedPatterns.flatMap(pattern => {
            try {
                return [new RegExp(pattern)];
            } catch (error: any) {
                this.logger.warn(`Invalid blocked pattern "${pattern}", skipping: ${error.message}`);
                return [];
            }
        });

        this._logInitialization();
    }

    /**
     * Parse and validate version range rules
     * @private
     */
    private _parseVersionRangeRules(rules: VersionRangeRule[]): VersionRangeRule[] {
        return rules.map((rule, index) => {
            if (!rule.package || !rule.range || !rule.strategy) {
                this.logger.warn(`Invalid version range rule at index ${index}, skipping`);
                return null;
            }

            if (rule.strategy === 'fallback') {
                this.logger.warn(`Strategy "fallback" for ${rule.package} is deprecated and works like "block": matching versions are hidden, so npm resolves to the highest allowed one`);
            }

            // Validate semver range
            try {
                const validRange = semver.validRange(rule.range);
                if (!validRange) {
                    this.logger.warn(`Invalid semver range "${rule.range}" for ${rule.package}, skipping`);
                    return null;
                }
            } catch (error: any) {
                this.logger.warn(`Error parsing range "${rule.range}" for ${rule.package}: ${error.message}`);
                return null;
            }

            return rule;
        }).filter((rule): rule is VersionRangeRule => rule !== null);
    }

    /**
     * Log initialization details
     * @private
     */
    private _logInitialization(): void {
        const features = this._getEnabledFeatures();
        this.logger.logInit(features);

        this.logger.debug(`[Init] Config mode: ${this.config.mode || 'not set'}`);
        this.logger.debug(`[Init] Blocked versions: ${this.securityRules.blockedVersions.length}`);
        this.logger.debug(`[Init] Blocked patterns: ${this.securityRules.blockedPatterns.length}`);

        if (this.securityRules.versionRangeRules.length > 0) {
            this.logger.info('Version range rules configured:');
            this.securityRules.versionRangeRules.forEach(rule => {
                const fallback = rule.strategy === 'fallback' ? ` -> ${rule.fallbackVersion}` : '';
                this.logger.debug(`  ${rule.package} ${rule.range} [${rule.strategy}${fallback}]`);
            });
        }

        if (this.config.mode === 'whitelist') {
            const summary = this.whitelistChecker.getSummary();
            this.logger.info(`Whitelist mode: ${summary.totalPackages} packages, ${summary.totalPatterns} patterns`);
        }

        if (this.config.authorFilter?.enabled) {
            const summary = this.authorChecker.getSummary();
            this.logger.info(`Author filtering enabled: ${summary.blockedAuthors} authors, ${summary.blockedEmails} emails, ${summary.blockedRegions} regions blocked`);
        }
    }

    /**
     * Get list of enabled features
     * @private
     */
    private _getEnabledFeatures(): string[] {
        const features: string[] = [];

        if (this.config.mode === 'whitelist') features.push('whitelist-mode');
        if (this.config.metrics?.enabled) features.push('metrics');
        if (this.config.cveCheck?.enabled) features.push('cve-checking');
        if (this.config.licenses?.allowed && this.config.licenses.allowed.length > 0) features.push('license-filtering');
        if (this.config.packageAge?.enabled) features.push('package-age-verification');
        if (this.config.authorFilter?.enabled) features.push('author-filtering');
        if (this.securityRules.versionRangeRules.length > 0) features.push('version-range-rules');
        if (this.securityRules.blockedPatterns.length > 0) features.push('pattern-blocking');
        if (this.securityRules.blockedVersions.length > 0) features.push('version-blocking');
        if (this.securityRules.blockedScopes.length > 0) features.push('scope-blocking');

        return features;
    }

    /**
     * Check if package name matches blocked patterns
     * @private
     */
    private _isBlockedByPattern(packageName: string): boolean {
        return this.blockedPatternRegexes.some(regex => regex.test(packageName));
    }

    /**
     * Check if package scope is allowed
     * @private
     */
    private _isScopeAllowed(packageName: string): boolean {
        // If not a scoped package, check if allowedScopes is empty
        if (!packageName.startsWith('@')) {
            return this.securityRules.allowedScopes.length === 0;
        }

        const scope = packageName.split('/')[0];

        // Check blacklist
        if (this.securityRules.blockedScopes.includes(scope)) {
            return false;
        }

        // Check whitelist (if exists)
        if (this.securityRules.allowedScopes.length > 0) {
            return this.securityRules.allowedScopes.includes(scope);
        }

        return true;
    }

    /**
     * Get version range rule for a specific package and version
     * @private
     */
    private _getVersionRangeRule(packageName: string, version: string): VersionRangeRule | null {
        return this.securityRules.versionRangeRules.find(rule => {
            if (rule.package !== packageName) {
                return false;
            }

            try {
                return semver.satisfies(version, rule.range);
            } catch (error: any) {
                this.logger.warn(`Error checking version ${version} against range ${rule.range}: ${error.message}`);
                return false;
            }
        }) || null;
    }

    /**
     * Register Express middleware to intercept package requests
     * Intercepts both metadata and tarball requests
     */
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    public register_middlewares(app: Application, _auth: IBasicAuth<SecurityConfig>, _storage: IStorageManager<SecurityConfig>): void {
        this.logger.info('[Middleware] Registering security filter middleware');
        this.logger.info(`[Middleware] Config mode: ${this.config.mode || 'NOT SET'}`);

        // Middleware to intercept all package requests
        app.use(async (req: Request, res: Response, next: NextFunction): Promise<void> => {
            try {
                // Only reads are filtered; awaiting before next() on POST/PUT breaks body parsing (#31).
                // `/-/` is Verdaccio's own API (login, tokens, search), not a package.
                if ((req.method !== 'GET' && req.method !== 'HEAD') || req.url.startsWith('/-/')) {
                    return next();
                }

                // Extract package name and version from URL
                // Tarball URLs: /:package/-/:filename.tgz
                // Scoped tarball URLs: /@scope/:package/-/:filename.tgz
                // Metadata URLs: /:package or /@scope/:package
                // npm sends scoped names URL-encoded (/@scope%2fname), so decode the path first
                let path = req.url.split('?')[0];
                try {
                    path = decodeURIComponent(path);
                } catch {
                    // malformed encoding: match the raw path
                }
                const urlMatch = path.match(/^\/(@[^/]+\/)?([^/]+)(?:\/-\/([^/]+\.tgz))?/);

                if (!urlMatch) {
                    // Not a package-related request, pass through
                    this.logger.debug(`[Middleware] Non-package request: ${req.method} ${req.url}`);
                    return next();
                }

                const scope = urlMatch[1] || '';
                const packageName = scope + urlMatch[2];
                const tarballFile = urlMatch[3];

                // Extract version from tarball filename if present
                let version: string | undefined;
                if (tarballFile) {
                    // This is a tarball download request - block it immediately
                    // npm names tarballs <unscoped name>-<version>.tgz. Cutting the known name off is
                    // exact; guessing with a regex misreads names like "foo-2" and versions like "1.0.0-beta-1".
                    const filePrefix = `${urlMatch[2]}-`;
                    version = tarballFile.startsWith(filePrefix)
                        ? tarballFile.slice(filePrefix.length, -'.tgz'.length)
                        : undefined;

                    this.logger.debug(`[Middleware] TARBALL REQUEST: ${packageName}@${version || 'unknown'}`);

                    // Apply all security checks for tarball downloads
                    const blockResult = await this._checkPackageBlock(packageName, version);

                    if (blockResult.blocked) {
                        this.logger.warn(`[Middleware] [X] BLOCKED TARBALL: ${packageName}@${version || '*'} - ${blockResult.reason}`);
                        this.metrics.recordBlock(packageName, version || '*', blockResult.reason);

                        // Return 403 Forbidden with detailed error
                        res.status(403).json({
                            error: 'Package blocked by security filter',
                            package: packageName,
                            version: version || 'all versions',
                            reason: blockResult.reason,
                            timestamp: new Date().toISOString()
                        });
                        return;
                    }

                    this.logger.debug(`[Middleware] [OK] ALLOWED TARBALL: ${packageName}@${version || 'unknown'}`);
                } else {
                    // This is a metadata request - intercept response and modify it
                    this.logger.debug(`[Middleware] METADATA REQUEST: ${packageName} - will intercept response`);

                    // Check if package should be blocked
                    const blockResult = await this._checkPackageBlock(packageName);

                    if (blockResult.blocked) {
                        this.logger.warn(`[Middleware] [X] BLOCKED METADATA: ${packageName} - ${blockResult.reason}`);

                        const blockedResponse = {
                            name: packageName,
                            versions: {},
                            'dist-tags': {},
                            security: {
                                blocked: true,
                                reason: blockResult.reason,
                                plugin: {
                                    name: 'verdaccio-security-filter',
                                    version: PLUGIN_VERSION,
                                    mode: this.config.mode || 'blacklist',
                                },
                                blockedAt: new Date().toISOString(),
                                rules: this._getAppliedRules(packageName),
                                message: `This package has been blocked by security filter: ${blockResult.reason}`,
                                contact: 'Please contact your registry administrator for more information',
                            },
                            _security: {
                                blocked: true,
                                reason: blockResult.reason,
                                blockedBy: 'verdaccio-security-filter',
                                blockedAt: new Date().toISOString(),
                            }
                        };

                        res.status(200).json(blockedResponse);
                        return;
                    } else {
                        this.logger.debug(`[Middleware] [OK] ALLOWED METADATA: ${packageName}`);
                    }
                }

                // Continue to next middleware
                next();
            } catch (error: any) {
                this.logger.error(`[Middleware] Error processing request: ${error.message}`);
                next(error);
            }
        });

        this.logger.info('[Middleware] Security filter middleware registered successfully');
    }

    /**
     * Metadata for a fully blocked package: no versions, plus the reason.
     * @private
     */
    private _blockedPackage(pkg: Package, reason: string, extra: Record<string, any> = {}): Package {
        return {
            ...pkg,
            versions: {},
            'dist-tags': {},
            security: {
                blocked: true,
                reason,
                ...extra,
                plugin: {
                    name: 'verdaccio-security-filter',
                    version: PLUGIN_VERSION,
                    mode: this.config.mode || 'blacklist',
                },
                blockedAt: new Date().toISOString(),
            }
        } as Package;
    }

    /**
     * Copy of the metadata without the given versions and the dist-tags pointing at them.
     * Removed dist-tags are not re-pointed: npm resolves ranges against what is left.
     * @private
     */
    private _removeVersions(pkg: Package, removed: string[]): Package {
        if (removed.length === 0) {
            return pkg;
        }

        const gone = new Set(removed);
        const versions = { ...pkg.versions };
        for (const version of gone) {
            delete versions[version];
        }

        const distTags = { ...pkg['dist-tags'] };
        for (const [tag, tagVersion] of Object.entries(distTags)) {
            if (gone.has(tagVersion as string)) {
                delete distTags[tag];
                this.logger.debug(`[filter_metadata] Removed dist-tag "${tag}" pointing to filtered version ${tagVersion}`);
            }
        }

        return { ...pkg, versions, 'dist-tags': distTags };
    }

    /**
     * Run a per-version check over every version and collect the ones it rejects.
     * `first` is the result to report for the package: the latest version's if it was rejected.
     * @private
     */
    private _rejectedVersions<T extends { allowed: boolean }>(pkg: Package, check: (data: Version) => T) {
        const all = Object.entries(pkg.versions || {});
        const results = all
            .map(([version, data]) => [version, check(data)] as [string, T])
            .filter(([, result]) => !result.allowed);
        const latest = results.find(([version]) => version === pkg['dist-tags']?.latest);

        return {
            results,
            versions: results.map(([version]) => version),
            first: (latest || results[0])?.[1],
            all: all.length > 0 && results.length === all.length,
        };
    }

    /**
     * Filter package metadata before returning to client
     * This provides CVE, License, and Age checking when metadata is available
     */
    public async filter_metadata(packageInfo: Package): Promise<Package> {
        let pkg = packageInfo;
        const packageName = pkg.name;
        this.logger.debug(`[filter_metadata] --> Processing: ${packageName}`);

        try {
            // 1. Whitelist/blacklist check (basic filtering)
            const blockResult = await this._checkPackageBlock(packageName);
            if (blockResult.blocked) {
                this.logger.warn(`[filter_metadata] BLOCKED: ${packageName}@* - ${blockResult.reason}`);
                this.metrics.recordBlock(packageName, '*', blockResult.reason);

                return this._blockedPackage(pkg, blockResult.reason, { rules: this._getAppliedRules(packageName) });
            }

            // 1b. Hide versions blocked by blockedVersions / versionRangeRules / whitelist.versions, so npm
            // resolves to an allowed version instead of picking a blocked one and failing on the tarball.
            const whitelistMode = this.config.mode === 'whitelist';
            if (whitelistMode || this.securityRules.blockedVersions.length > 0 || this.securityRules.versionRangeRules.length > 0) {
                const ruleBlocked = Object.keys(pkg.versions || {}).filter(version =>
                    this._versionBlockReason(packageName, version) !== null ||
                    (whitelistMode && !this.whitelistChecker.isWhitelisted(packageName, version).allowed)
                );

                if (ruleBlocked.length > 0) {
                    this.logger.warn(`[filter_metadata] RULE FILTERED: ${packageName}: ${ruleBlocked.join(', ')}`);
                    pkg = this._removeVersions(pkg, ruleBlocked);
                }
            }

            // 2. CVE Check - one lookup per package, versions are matched locally
            if (this.config.cveCheck?.enabled) {
                const versions = Object.keys(pkg.versions || {});
                let vulnerableVersions: string[] = [];

                try {
                    const results = await this.cveChecker.checkVersions(packageName, versions);
                    vulnerableVersions = results.filter(result => result.isVulnerable).map(result => result.version);
                } catch (error: any) {
                    this.logger.error(`[filter_metadata] CVE check failed for ${packageName}: ${error.message}`);

                    if (this.config.errorHandling?.onCveCheckError === 'fail-closed') {
                        const reason = `CVE check failed (fail-closed mode): ${error.message}`;
                        this.metrics.recordBlock(packageName, '*', reason);

                        return this._blockedPackage(pkg, reason);
                    }
                }

                if (vulnerableVersions.length > 0 && !this.config.cveCheck.autoBlock) {
                    this.logger.warn(`[filter_metadata] CVE found in ${packageName}: ${vulnerableVersions.length} vulnerable version(s), autoBlock is off`);
                }

                // If configured to auto-block, remove only the vulnerable versions -
                // other versions of the same package may not be affected.
                if (this.config.cveCheck.autoBlock && vulnerableVersions.length > 0) {
                    const reason = `Package has ${vulnerableVersions.length} vulnerable version(s)`;

                    // Every version is vulnerable - nothing safe remains, so block the whole package.
                    if (vulnerableVersions.length === versions.length) {
                        this.logger.warn(`[filter_metadata] CVE BLOCKED: ${packageName} - ${reason}`);
                        this.metrics.recordBlock(packageName, '*', reason);

                        return this._blockedPackage(pkg, reason, { vulnerableVersions });
                    }

                    this.logger.warn(`[filter_metadata] CVE FILTERED: ${packageName} - ${reason}: ${vulnerableVersions.join(', ')}`);
                    for (const version of vulnerableVersions) {
                        this.metrics.recordBlock(packageName, version, reason);
                    }
                    pkg = this._removeVersions(pkg, vulnerableVersions);
                }
            }

            // 3. License Check - every version; only the offending ones are removed
            if (this.config.licenses && this.config.licenses.allowed && this.config.licenses.allowed.length > 0) {
                const rejected = this._rejectedVersions(pkg, data => this.licenseChecker.checkLicense(data));

                if (rejected.all) {
                    const reason = rejected.first.reason || 'License not allowed';
                    this.logger.warn(`[filter_metadata] LICENSE BLOCKED: ${packageName} - ${reason}`);
                    this.metrics.recordBlock(packageName, '*', reason);

                    return this._blockedPackage(pkg, reason, { license: rejected.first.license });
                }

                if (rejected.versions.length > 0) {
                    this.logger.warn(`[filter_metadata] LICENSE FILTERED: ${packageName}: ${rejected.versions.join(', ')}`);
                    for (const [version, result] of rejected.results) {
                        this.metrics.recordBlock(packageName, version, result.reason || 'License not allowed');
                    }
                    pkg = this._removeVersions(pkg, rejected.versions);
                }
            }

            // 4. Package Age Check
            if (this.config.packageAge?.enabled) {
                // 4a. Check overall package age (minPackageAgeDays)
                const ageResult = this.packageAgeChecker.checkPackageAge(pkg);
                if (!ageResult.allowed && !ageResult.warnOnly) {
                    const reason = ageResult.reason || 'Package too new';
                    this.logger.warn(`[filter_metadata] AGE BLOCKED: ${packageName} - ${reason}`);
                    this.metrics.recordBlock(packageName, '*', reason);

                    return this._blockedPackage(pkg, reason, { ageDays: ageResult.ageDays });
                } else if (!ageResult.allowed && ageResult.warnOnly) {
                    this.logger.warn(`[filter_metadata] AGE WARNING: ${packageName} - ${ageResult.reason} (warn-only mode)`);
                }

                // 4b. Check per-version age (minVersionAgeDays) — filter out versions that are too new
                if (this.config.packageAge.minVersionAgeDays) {
                    const removedVersions: string[] = [];

                    for (const version of Object.keys(pkg.versions || {})) {
                        const versionAgeResult = this.packageAgeChecker.checkVersionAge(pkg, version);
                        if (!versionAgeResult.allowed && !versionAgeResult.warnOnly) {
                            this.logger.warn(`[filter_metadata] VERSION AGE FILTERED: ${packageName}@${version} - ${versionAgeResult.reason}`);
                            this.metrics.recordBlock(packageName, version, versionAgeResult.reason || 'Version too new');
                            removedVersions.push(version);
                        } else if (!versionAgeResult.allowed && versionAgeResult.warnOnly) {
                            this.logger.warn(`[filter_metadata] VERSION AGE WARNING: ${packageName}@${version} - ${versionAgeResult.reason} (warn-only mode)`);
                        }
                    }

                    pkg = this._removeVersions(pkg, removedVersions);
                }
            }

            // 5. Author Filter Check
            if (this.config.authorFilter?.enabled) {
                const rejected = this._rejectedVersions(pkg, data => this.authorChecker.checkAuthor(data));

                if (rejected.versions.length > 0 && this.config.authorFilter.warnOnly) {
                    this.logger.warn(`[filter_metadata] AUTHOR WARNING: ${packageName}: ${rejected.versions.join(', ')} - ${rejected.first.reason} (warn-only mode)`);
                } else if (rejected.versions.length > 0) {
                    for (const [version, result] of rejected.results) {
                        this.metrics.record({
                            timestamp: new Date().toISOString(),
                            event: 'author_blocked',
                            packageName,
                            version: rejected.all ? '*' : version,
                            reason: result.reason || 'Author not allowed',
                            metadata: {
                                blockedBy: result.blockedBy,
                                authorInfo: result.authorInfo,
                            },
                        });
                        if (rejected.all) {
                            break; // one event for the whole package
                        }
                    }

                    if (rejected.all) {
                        const reason = rejected.first.reason || 'Author not allowed';
                        this.logger.warn(`[filter_metadata] AUTHOR BLOCKED: ${packageName} - ${reason}`);

                        return this._blockedPackage(pkg, reason, {
                            blockedBy: rejected.first.blockedBy,
                            authorInfo: rejected.first.authorInfo,
                        });
                    }

                    this.logger.warn(`[filter_metadata] AUTHOR FILTERED: ${packageName}: ${rejected.versions.join(', ')}`);
                    pkg = this._removeVersions(pkg, rejected.versions);
                }
            }

            this.logger.debug(`[filter_metadata] [OK] ALLOWED: ${packageName}`);
            return pkg;

        } catch (error: any) {
            this.logger.error(`[filter_metadata] Error processing ${packageName}: ${error.message}`);
            const errorStrategy = this.config.errorHandling?.onFilterError || 'fail-open';

            if (errorStrategy === 'fail-closed') {
                this.logger.warn(`[filter_metadata] Error handling: fail-closed - BLOCKING ${packageName}`);
                this.metrics.recordBlock(packageName, '*', `Error during processing: ${error.message}`);

                // use original on error path
                return this._blockedPackage(packageInfo, `Error during security processing (fail-closed mode): ${error.message}`);
            }

            this.logger.warn(`[filter_metadata] Error handling: fail-open - ALLOWING ${packageName}`);
            return packageInfo;  // use original on error path
        }
    }

    /**
     * Why a specific version is blocked by blockedVersions / versionRangeRules, or null.
     * @private
     */
    private _versionBlockReason(packageName: string, version: string): string | null {
        if (this.securityRules.blockedVersions.includes(`${packageName}@${version}`)) {
            return 'Exact version match in blocklist';
        }

        const rangeRule = this._getVersionRangeRule(packageName, version);
        return rangeRule ? `Version matches blocked range: ${rangeRule.range}` : null;
    }

    /**
     * Check if package should be blocked (used by middleware)
     * @private
     */
    private async _checkPackageBlock(packageName: string, version?: string): Promise<{ blocked: boolean; reason: string }> {
        // 1. Whitelist mode
        if (this.config.mode === 'whitelist') {
            const whitelistCheck = this.whitelistChecker.isWhitelisted(packageName, version);
            if (!whitelistCheck.allowed) {
                return { blocked: true, reason: whitelistCheck.reason || 'Package is not in whitelist' };
            }
        }

        // 2. Blocked patterns
        if (this._isBlockedByPattern(packageName)) {
            return { blocked: true, reason: 'Package name matches blocked pattern' };
        }

        // 3. Scopes
        if (!this._isScopeAllowed(packageName)) {
            return { blocked: true, reason: 'Package scope not allowed' };
        }

        // 4. Exact version blocking and version range rules
        const versionReason = version ? this._versionBlockReason(packageName, version) : null;
        if (versionReason) {
            return { blocked: true, reason: versionReason };
        }

        return { blocked: false, reason: '' };
    }

    /**
     * Get applied security rules for a package
     * @private
     */
    private _getAppliedRules(packageName: string): Record<string, any> {
        const rules: Record<string, any> = {};

        // Check which rules apply to this package
        if (this.config.mode === 'whitelist') {
            rules.mode = 'whitelist';
            rules.whitelisted = false;
        }

        const blockedPattern = this.blockedPatternRegexes.find(regex => regex.test(packageName));
        if (blockedPattern) {
            rules.blockedPattern = blockedPattern.source;
        }

        if (packageName.startsWith('@')) {
            const scope = packageName.split('/')[0];
            if (this.securityRules.blockedScopes.includes(scope)) {
                rules.blockedScope = scope;
            }
            if (this.securityRules.allowedScopes.length > 0 && !this.securityRules.allowedScopes.includes(scope)) {
                rules.scopeNotInAllowedList = scope;
                rules.allowedScopes = this.securityRules.allowedScopes;
            }
        }

        const versionRules = this.securityRules.versionRangeRules.filter(rule => rule.package === packageName);
        if (versionRules.length > 0) {
            rules.versionRangeRules = versionRules.map(rule => ({
                range: rule.range,
                strategy: rule.strategy,
                reason: rule.reason,
            }));
        }

        return rules;
    }

    /**
     * Cleanup plugin resources
     * Should be called when Verdaccio shuts down
     */
    destroy(): void {
        this.logger.info('[Cleanup] Shutting down security filter plugin');

        try {
            this.cveChecker.destroy();
            this.metrics.cleanup();
            this.logger.info('[Cleanup] Plugin resources cleaned up successfully');
        } catch (error: any) {
            this.logger.error(`[Cleanup] Error during cleanup: ${error.message}`);
        }
    }
}

// Export utility classes for testing
export { SecurityLogger } from './lib/logger';
export { MetricsCollector } from './lib/metrics';
export { WhitelistChecker } from './lib/whitelist-checker';
export { CVEChecker } from './lib/cve-checker';
export { LicenseChecker } from './lib/license-checker';
export { PackageAgeChecker } from './lib/package-age-checker';
export { AuthorChecker } from './lib/author-checker';

export * from './types';
