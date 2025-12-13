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
                        // Intercept the response
                        const originalSend = res.send;
                        const originalJson = res.json;
                        // eslint-disable-next-line @typescript-eslint/no-this-alias
                        const self = this;

                        // Override res.json to intercept JSON responses
                        res.json = function(body: any): Response {
                            if (body && typeof body === 'object' && body.name === packageName) {
                                // This is package metadata - modify it to show blocked info
                                self.logger.warn(`[Middleware] [X] BLOCKED METADATA: ${packageName} - ${blockResult.reason}`);
                                self.logger.info(`[Middleware] Modifying response to show blocking info`);

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
                                            mode: self.config.mode || 'blacklist',
                                        },
                                        blockedAt: new Date().toISOString(),
                                        rules: self._getAppliedRules(packageName),
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

                                return originalJson.call(this, blockedResponse);
                            }
                            return originalJson.call(this, body);
                        };

                        // Override res.send for non-JSON responses
                        res.send = function(body: any): Response {
                            if (typeof body === 'string') {
                                try {
                                    const parsed = JSON.parse(body);
                                    if (parsed && parsed.name === packageName) {
                                        self.logger.warn(`[Middleware] [X] BLOCKED METADATA: ${packageName} - ${blockResult.reason}`);

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
                                                    mode: self.config.mode || 'blacklist',
                                                },
                                                blockedAt: new Date().toISOString(),
                                                rules: self._getAppliedRules(packageName),
                                                message: `This package has been blocked by security filter: ${blockResult.reason}`,
                                                contact: 'Please contact your registry administrator for more information',
                                            }
                                        };

                                        return originalSend.call(this, JSON.stringify(blockedResponse));
                                    }
                                } catch {
                                    // Not JSON, pass through
                                }
                            }
                            return originalSend.call(this, body);
                        };
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
        const packageName = packageInfo.name;
        this.logger.info(`[filter_metadata] --> Processing: ${packageName}`);

        try {
            // 1. Whitelist/blacklist check (basic filtering)
            const blockResult = await this._checkPackageBlock(packageName);
            if (blockResult.blocked) {
                this.logger.warn(`[filter_metadata] BLOCKED: ${packageName}@* - ${blockResult.reason}`);
                this.metrics.recordBlock(packageName, '*', blockResult.reason);

                // Return empty versions with security field
                return {
                    ...packageInfo,
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

            // 2. CVE Check - check all versions
            if (this.config.cveCheck?.enabled) {
                const versions = Object.keys(packageInfo.versions || {});
                const vulnerableVersions: string[] = [];

                for (const version of versions) {
                    const cveResult = await this.cveChecker.checkPackage(packageName, version);
                    if (cveResult.isVulnerable) {
                        vulnerableVersions.push(version);
                        this.logger.warn(`[filter_metadata] CVE found in ${packageName}@${version}: ${cveResult.vulnerabilities.length} vulnerabilities`);
                    }
                }

                // If configured to auto-block and vulnerabilities found
                if (this.config.cveCheck.autoBlock && vulnerableVersions.length > 0) {
                    const reason = `Package has ${vulnerableVersions.length} vulnerable version(s)`;
                    this.logger.warn(`[filter_metadata] CVE BLOCKED: ${packageName} - ${reason}`);
                    this.metrics.recordBlock(packageName, '*', reason);

                    return {
                        ...packageInfo,
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
                const latestVersion = packageInfo['dist-tags']?.latest;
                if (latestVersion && packageInfo.versions?.[latestVersion]) {
                    const versionData = packageInfo.versions[latestVersion];
                    const licenseResult = this.licenseChecker.checkLicense(versionData);

                    if (!licenseResult.allowed) {
                        this.logger.warn(`[filter_metadata] LICENSE BLOCKED: ${packageName} - ${licenseResult.reason}`);
                        this.metrics.recordBlock(packageName, '*', licenseResult.reason || 'License not allowed');

                        return {
                            ...packageInfo,
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
                const ageResult = this.packageAgeChecker.checkPackageAge(packageInfo);
                if (!ageResult.allowed && !ageResult.warnOnly) {
                    this.logger.warn(`[filter_metadata] AGE BLOCKED: ${packageName} - ${ageResult.reason}`);
                    this.metrics.recordBlock(packageName, '*', ageResult.reason || 'Package too new');

                    return {
                        ...packageInfo,
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
            }

            this.logger.info(`[filter_metadata] [OK] ALLOWED: ${packageName}`);
            return packageInfo;

        } catch (error: any) {
            this.logger.error(`[filter_metadata] Error processing ${packageName}: ${error.message}`);
            const errorStrategy = this.config.errorHandling?.onFilterError || 'fail-open';

            if (errorStrategy === 'fail-closed') {
                this.logger.warn(`[filter_metadata] Error handling: fail-closed - BLOCKING ${packageName}`);
                this.metrics.recordBlock(packageName, '*', `Error during processing: ${error.message}`);

                return {
                    ...packageInfo,
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
            return packageInfo;
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
}

// Export utility classes for testing
export { SecurityLogger } from './lib/logger';
export { MetricsCollector } from './lib/metrics';
export { WhitelistChecker } from './lib/whitelist-checker';
export { CVEChecker } from './lib/cve-checker';
export { LicenseChecker } from './lib/license-checker';
export { PackageAgeChecker } from './lib/package-age-checker';

export * from './types';
