import { IPluginMiddleware, IPluginStorageFilter, PluginOptions, IBasicAuth, IStorageManager, Package } from '@verdaccio/types';
import * as semver from 'semver';
import { Application, Request, Response, NextFunction } from 'express';

import { SecurityConfig, SecurityRules, VersionRangeRule } from './types';
import { SecurityLogger } from './lib/logger';
import { MetricsCollector } from './lib/metrics';
import { WhitelistChecker } from './lib/whitelist-checker';
import { CVEChecker } from './lib/cve-checker';
import { LicenseChecker } from './lib/license-checker';
import { PackageAgeChecker } from './lib/package-age-checker';
import { AuthorChecker } from './lib/author-checker';

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
                onLicenseCheckError: 'fail-open',
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
            minPackageSize: this.config.minPackageSize || 0,
            maxPackageSize: this.config.maxPackageSize || 100 * 1024 * 1024, // 100MB
            allowedScopes: this.config.allowedScopes || [],
            blockedScopes: this.config.blockedScopes || [],
            enforceChecksum: this.config.enforceChecksum !== false,
            versionRangeRules: this._parseVersionRangeRules(this.config.versionRangeRules || [])
        };

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

            if (rule.strategy === 'fallback' && !rule.fallbackVersion) {
                this.logger.warn(`Fallback strategy requires fallbackVersion for ${rule.package}, skipping`);
                return null;
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
        return this.securityRules.blockedPatterns.some(pattern => {
            const regex = new RegExp(pattern);
            return regex.test(packageName);
        });
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
                // Extract package name and version from URL
                // Tarball URLs: /:package/-/:filename.tgz
                // Scoped tarball URLs: /@scope/:package/-/:filename.tgz
                // Metadata URLs: /:package or /@scope/:package
                const urlMatch = req.url.match(/^\/(@[^/]+\/)?([^/]+)(?:\/-\/([^/]+\.tgz))?/);

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
                    const versionMatch = tarballFile.match(/-([\d.]+(?:-[a-zA-Z0-9.]+)?)\.tgz$/);
                    version = versionMatch ? versionMatch[1] : undefined;

                    this.logger.info(`[Middleware] TARBALL REQUEST: ${packageName}@${version || 'unknown'}`);

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

                    this.logger.info(`[Middleware] [OK] ALLOWED TARBALL: ${packageName}@${version || 'unknown'}`);
                } else {
                    // This is a metadata request - intercept response and modify it
                    this.logger.info(`[Middleware] METADATA REQUEST: ${packageName} - will intercept response`);

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
                                    version: '1.0.0',
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
                        this.logger.info(`[Middleware] [OK] ALLOWED METADATA: ${packageName}`);
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
     * Filter package metadata before returning to client
     * This provides CVE, License, and Age checking when metadata is available
     */
    public async filter_metadata(packageInfo: Package): Promise<Package> {
        let pkg = packageInfo;
        const packageName = pkg.name;
        this.logger.info(`[filter_metadata] --> Processing: ${packageName}`);

        try {
            // 1. Whitelist/blacklist check (basic filtering)
            const blockResult = await this._checkPackageBlock(packageName);
            if (blockResult.blocked) {
                this.logger.warn(`[filter_metadata] BLOCKED: ${packageName}@* - ${blockResult.reason}`);
                this.metrics.recordBlock(packageName, '*', blockResult.reason);

                // Return empty versions with security field
                return {
                    ...pkg,
                    versions: {},
                    'dist-tags': {},
                    security: {
                        blocked: true,
                        reason: blockResult.reason,
                        plugin: {
                            name: 'verdaccio-security-filter',
                            version: '2.0.0',
                            mode: this.config.mode || 'blacklist',
                        },
                        blockedAt: new Date().toISOString(),
                        rules: this._getAppliedRules(packageName),
                    }
                } as Package;
            }

            // 2. CVE Check - check versions in controlled batches
            if (this.config.cveCheck?.enabled) {
                const versions = Object.keys(pkg.versions || {});
                const vulnerableVersions: string[] = [];

                const BATCH_SIZE = 10;
                for (let i = 0; i < versions.length; i += BATCH_SIZE) {
                    const batch = versions.slice(i, i + BATCH_SIZE);
                    const results = await Promise.allSettled(
                        batch.map(version => this.cveChecker.checkPackage(packageName, version))
                    );

                    results.forEach((result, index) => {
                        if (result.status === 'fulfilled' && result.value.isVulnerable) {
                            const version = batch[index];
                            vulnerableVersions.push(version);
                            this.logger.warn(`[filter_metadata] CVE found in ${packageName}@${version}: ${result.value.vulnerabilities.length} vulnerabilities`);
                        } else if (result.status === 'rejected') {
                            this.logger.error(`[filter_metadata] CVE check failed for ${packageName}@${batch[index]}: ${result.reason}`);
                        }
                    });
                }

                // If configured to auto-block and vulnerabilities found
                if (this.config.cveCheck.autoBlock && vulnerableVersions.length > 0) {
                    const reason = `Package has ${vulnerableVersions.length} vulnerable version(s)`;
                    this.logger.warn(`[filter_metadata] CVE BLOCKED: ${packageName} - ${reason}`);
                    this.metrics.recordBlock(packageName, '*', reason);

                    return {
                        ...pkg,
                        versions: {},
                        'dist-tags': {},
                        security: {
                            blocked: true,
                            reason,
                            vulnerableVersions,
                            plugin: {
                                name: 'verdaccio-security-filter',
                                version: '2.0.0',
                            },
                            blockedAt: new Date().toISOString(),
                        }
                    } as Package;
                }
            }

            // 3. License Check - check latest version
            if (this.config.licenses && this.config.licenses.allowed && this.config.licenses.allowed.length > 0) {
                const latestVersion = pkg['dist-tags']?.latest;
                if (latestVersion && pkg.versions?.[latestVersion]) {
                    const versionData = pkg.versions[latestVersion];
                    const licenseResult = this.licenseChecker.checkLicense(versionData);

                    if (!licenseResult.allowed) {
                        this.logger.warn(`[filter_metadata] LICENSE BLOCKED: ${packageName} - ${licenseResult.reason}`);
                        this.metrics.recordBlock(packageName, '*', licenseResult.reason || 'License not allowed');

                        return {
                            ...pkg,
                            versions: {},
                            'dist-tags': {},
                            security: {
                                blocked: true,
                                reason: licenseResult.reason || 'License not allowed',
                                license: licenseResult.license,
                                plugin: {
                                    name: 'verdaccio-security-filter',
                                    version: '2.0.0',
                                },
                                blockedAt: new Date().toISOString(),
                            }
                        } as Package;
                    }
                }
            }

            // 4. Package Age Check
            if (this.config.packageAge?.enabled) {
                // 4a. Check overall package age (minPackageAgeDays)
                const ageResult = this.packageAgeChecker.checkPackageAge(pkg);
                if (!ageResult.allowed && !ageResult.warnOnly) {
                    this.logger.warn(`[filter_metadata] AGE BLOCKED: ${packageName} - ${ageResult.reason}`);
                    this.metrics.recordBlock(packageName, '*', ageResult.reason || 'Package too new');

                    return {
                        ...pkg,
                        versions: {},
                        'dist-tags': {},
                        security: {
                            blocked: true,
                            reason: ageResult.reason || 'Package too new',
                            ageDays: ageResult.ageDays,
                            plugin: {
                                name: 'verdaccio-security-filter',
                                version: '2.0.0',
                            },
                            blockedAt: new Date().toISOString(),
                        }
                    } as Package;
                } else if (!ageResult.allowed && ageResult.warnOnly) {
                    this.logger.warn(`[filter_metadata] AGE WARNING: ${packageName} - ${ageResult.reason} (warn-only mode)`);
                }

                // 4b. Check per-version age (minVersionAgeDays) — filter out versions that are too new
                if (this.config.packageAge.minVersionAgeDays) {
                    const filteredVersions = { ...pkg.versions };
                    const removedVersions: string[] = [];

                    for (const version of Object.keys(filteredVersions)) {
                        const versionAgeResult = this.packageAgeChecker.checkVersionAge(pkg, version);
                        if (!versionAgeResult.allowed && !versionAgeResult.warnOnly) {
                            this.logger.warn(`[filter_metadata] VERSION AGE FILTERED: ${packageName}@${version} - ${versionAgeResult.reason}`);
                            this.metrics.recordBlock(packageName, version, versionAgeResult.reason || 'Version too new');
                            delete filteredVersions[version];
                            removedVersions.push(version);
                        } else if (!versionAgeResult.allowed && versionAgeResult.warnOnly) {
                            this.logger.warn(`[filter_metadata] VERSION AGE WARNING: ${packageName}@${version} - ${versionAgeResult.reason} (warn-only mode)`);
                        }
                    }

                    if (removedVersions.length > 0) {
                        this.logger.info(`[filter_metadata] Removed ${removedVersions.length} too-new version(s) from ${packageName}: ${removedVersions.join(', ')}`);

                        // Also remove filtered versions from dist-tags
                        const filteredDistTags = { ...pkg['dist-tags'] };
                        for (const [tag, tagVersion] of Object.entries(filteredDistTags)) {
                            if (removedVersions.includes(tagVersion)) {
                                delete filteredDistTags[tag];
                                this.logger.debug(`[filter_metadata] Removed dist-tag "${tag}" pointing to filtered version ${tagVersion}`);
                            }
                        }

                        pkg = {
                            ...pkg,
                            versions: filteredVersions,
                            'dist-tags': filteredDistTags,
                        };
                    }
                }
            }

            // 5. Author Filter Check
            if (this.config.authorFilter?.enabled) {
                const latestVersion = pkg['dist-tags']?.latest;
                if (latestVersion && pkg.versions?.[latestVersion]) {
                    const versionData = pkg.versions[latestVersion];
                    const authorResult = this.authorChecker.checkAuthor(versionData);

                    if (!authorResult.allowed && !this.config.authorFilter.warnOnly) {
                        this.logger.warn(`[filter_metadata] AUTHOR BLOCKED: ${packageName} - ${authorResult.reason}`);
                        this.metrics.record({
                            timestamp: new Date().toISOString(),
                            event: 'author_blocked',
                            packageName,
                            version: latestVersion,
                            reason: authorResult.reason || 'Author not allowed',
                            metadata: {
                                blockedBy: authorResult.blockedBy,
                                authorInfo: authorResult.authorInfo,
                            },
                        });

                        return {
                            ...pkg,
                            versions: {},
                            'dist-tags': {},
                            security: {
                                blocked: true,
                                reason: authorResult.reason || 'Author not allowed',
                                blockedBy: authorResult.blockedBy,
                                authorInfo: authorResult.authorInfo,
                                plugin: {
                                    name: 'verdaccio-security-filter',
                                    version: '2.0.0',
                                },
                                blockedAt: new Date().toISOString(),
                            }
                        } as Package;
                    } else if (!authorResult.allowed && this.config.authorFilter.warnOnly) {
                        this.logger.warn(`[filter_metadata] AUTHOR WARNING: ${packageName} - ${authorResult.reason} (warn-only mode)`);
                    }
                }
            }

            this.logger.info(`[filter_metadata] [OK] ALLOWED: ${packageName}`);
            return pkg;

        } catch (error: any) {
            this.logger.error(`[filter_metadata] Error processing ${packageName}: ${error.message}`);
            const errorStrategy = this.config.errorHandling?.onFilterError || 'fail-open';

            if (errorStrategy === 'fail-closed') {
                this.logger.warn(`[filter_metadata] Error handling: fail-closed - BLOCKING ${packageName}`);
                this.metrics.recordBlock(packageName, '*', `Error during processing: ${error.message}`);

                return {
                    ...packageInfo,  // use original on error path
                    versions: {},
                    'dist-tags': {},
                    security: {
                        blocked: true,
                        reason: `Error during security processing (fail-closed mode): ${error.message}`,
                        plugin: {
                            name: 'verdaccio-security-filter',
                            version: '2.0.0',
                        },
                        blockedAt: new Date().toISOString(),
                    }
                } as Package;
            }

            this.logger.warn(`[filter_metadata] Error handling: fail-open - ALLOWING ${packageName}`);
            return packageInfo;  // use original on error path
        }
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

        // 4. Exact version blocking
        if (version) {
            const versionKey = `${packageName}@${version}`;
            if (this.securityRules.blockedVersions.includes(versionKey)) {
                return { blocked: true, reason: 'Exact version match in blocklist' };
            }

            // 5. Version range rules
            const rangeRule = this._getVersionRangeRule(packageName, version);
            if (rangeRule && rangeRule.strategy === 'block') {
                return { blocked: true, reason: `Version matches blocked range: ${rangeRule.range}` };
            }
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

        if (this._isBlockedByPattern(packageName)) {
            rules.blockedPattern = this.securityRules.blockedPatterns.find(pattern => {
                const regex = new RegExp(pattern);
                return regex.test(packageName);
            });
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
