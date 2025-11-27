import { IPluginStorageFilter, Logger, Package, PluginOptions } from '@verdaccio/types';

import * as semver from 'semver';

import { FilterResult, SecurityConfig, SecurityRules, VersionData, VersionRangeRule } from './types';

export default class SecurityFilterPlugin implements IPluginStorageFilter<SecurityConfig> {
    public logger: Logger;
    public config: SecurityConfig;
    private securityRules: SecurityRules;

    /**
     * Creates a new SecurityFilterPlugin instance
     * @param {SecurityConfig} config - Plugin configuration
     * @param {PluginOptions} options - Verdaccio plugin options
     */
    constructor(config: SecurityConfig, options: PluginOptions<SecurityConfig>) {
        this.config = config;
        this.logger = options.logger;

        // Security rules configuration
        this.securityRules = {
            blockedVersions: config.blockedVersions || [],
            blockedPatterns: config.blockedPatterns || [],
            minPackageSize: config.minPackageSize || 0,
            maxPackageSize: config.maxPackageSize || 100 * 1024 * 1024, // 100MB
            allowedScopes: config.allowedScopes || [],
            blockedScopes: config.blockedScopes || [],
            enforceChecksum: config.enforceChecksum !== false,
            versionRangeRules: this._parseVersionRangeRules(config.versionRangeRules || [])
        };

        this.logger.info('[Security Filter] Plugin initialized');
        this._logVersionRangeRules();
    }

    /**
     * Filter package metadata before serving
     * @param {Package} packageInfo - Package metadata
     * @returns {Package} Filtered package metadata
     */
    public async filter_metadata(packageInfo: Package): Promise<Package> {
        const packageName = packageInfo.name;

        try {
            // 1. Check blocked patterns
            if (this._isBlockedByPattern(packageName)) {
                this.logger.warn(`[Security Filter] Package blocked by pattern: ${packageName}`);
                return this._createBlockedResponse(packageName, 'Package name matches blocked pattern');
            }

            // 2. Check scopes
            if (!this._isScopeAllowed(packageName)) {
                this.logger.warn(`[Security Filter] Package blocked by scope: ${packageName}`);
                return this._createBlockedResponse(packageName, 'Package scope not allowed');
            }

            // 3. Filter versions (including range rules)
            if (packageInfo.versions) {
                const filterResult = this._filterVersions(packageInfo.versions, packageName);
                packageInfo.versions = filterResult.versions;

                // Update dist-tags if versions were modified
                if (filterResult.fallbacksApplied.length > 0 && packageInfo['dist-tags']) {
                    packageInfo['dist-tags'] = this._updateDistTags(
                        packageInfo['dist-tags'],
                        filterResult.versions
                    );
                }
            }

            // 4. Add security metadata
            // Using strict types, we might need to cast or extend the Package type if _security is not standard
            (packageInfo as any)._security = {
                scanned: true,
                scanDate: new Date().toISOString(),
                filteredBy: 'verdaccio-security-filter',
                blockedVersions: this._getBlockedVersionsList(packageName),
                fallbackVersions: this._getFallbackVersionsList(packageName)
            };

            return packageInfo;
        } catch (error) {
            this.logger.error(`[Security Filter] Error filtering package ${packageName}: ${error}`);
            throw error;
        }
    }

    /**
     * Validate package before publish
     * @param {string} packageName - Package name
     * @param {string} version - Version to publish
     * @param {Buffer} [tarball] - Package tarball
     * @returns {Promise<boolean>} True if validation passes
     */
    public async validate_publish(packageName: string, version: string, tarball?: Buffer): Promise<boolean> {
        this.logger.info(`[Security Filter] Validating publish: ${packageName}@${version}`);

        // 1. Check package size
        if (tarball && tarball.length) {
            const size = tarball.length;
            if (size < this.securityRules.minPackageSize) {
                throw new Error(`Package size ${size} bytes is below minimum ${this.securityRules.minPackageSize} bytes`);
            }
            if (size > this.securityRules.maxPackageSize) {
                throw new Error(`Package size ${size} bytes exceeds maximum ${this.securityRules.maxPackageSize} bytes`);
            }
        }

        // 2. Check exact blocked versions
        const versionKey = `${packageName}@${version}`;
        if (this.securityRules.blockedVersions.includes(versionKey)) {
            throw new Error(`Version ${versionKey} is blocked due to security concerns`);
        }

        // 3. Check version range rules
        const rangeRule = this._getVersionRangeRule(packageName, version);
        if (rangeRule) {
            const message = rangeRule.reason
                ? `Version ${version} is blocked by range rule: ${rangeRule.reason}`
                : `Version ${version} falls within blocked range: ${rangeRule.range}`;
            throw new Error(message);
        }

        // 4. Validate metadata
        if (!this._validateMetadata(packageName, version)) {
            throw new Error(`Package metadata validation failed for ${versionKey}`);
        }

        return true;
    }

    /**
     * Parse and validate version range rules
     * @private
     * @param {VersionRangeRule[]} rules - Raw version range rules from config
     * @returns {VersionRangeRule[]} Validated rules
     */
    private _parseVersionRangeRules(rules: VersionRangeRule[]): VersionRangeRule[] {
        return rules.map((rule, index) => {
            if (!rule.package || !rule.range || !rule.strategy) {
                this.logger.warn(`[Security Filter] Invalid version range rule at index ${index}, skipping`);
                return null;
            }

            if (rule.strategy === 'fallback' && !rule.fallbackVersion) {
                this.logger.warn(`[Security Filter] Fallback strategy requires fallbackVersion for ${rule.package}, skipping`);
                return null;
            }

            // Validate semver range
            try {
                const validRange = semver.validRange(rule.range);
                if (!validRange) {
                    this.logger.warn(`[Security Filter] Invalid semver range "${rule.range}" for ${rule.package}, skipping`);
                    return null;
                }
            } catch (error: any) {
                this.logger.warn(`[Security Filter] Error parsing range "${rule.range}" for ${rule.package}:`, error.message);
                return null;
            }

            return rule;
        }).filter((rule): rule is VersionRangeRule => rule !== null);
    }

    /**
     * Log configured version range rules
     * @private
     */
    private _logVersionRangeRules(): void {
        if (this.securityRules.versionRangeRules.length > 0) {
            this.logger.info('[Security Filter] Version range rules:');
            this.securityRules.versionRangeRules.forEach(rule => {
                const fallback = rule.strategy === 'fallback' ? ` -> ${rule.fallbackVersion}` : '';
                this.logger.info(`  - ${rule.package} ${rule.range} [${rule.strategy}${fallback}]`);
            });
        }
    }

    /**
     * Check if package name matches blocked patterns
     * @private
     * @param {string} packageName - Package name to check
     * @returns {boolean} True if blocked
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
     * @param {string} packageName - Package name to check
     * @returns {boolean} True if allowed
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
     * @param {string} packageName - Package name
     * @param {string} version - Version to check
     * @returns {VersionRangeRule|null} Matching rule or null
     */
    private _getVersionRangeRule(packageName: string, version: string): VersionRangeRule | null {
        return this.securityRules.versionRangeRules.find(rule => {
            if (rule.package !== packageName) {
                return false;
            }

            try {
                return semver.satisfies(version, rule.range);
            } catch (error: any) {
                this.logger.warn(`[Security Filter] Error checking version ${version} against range ${rule.range}:`, error.message);
                return false;
            }
        }) || null;
    }

    /**
     * Filter versions based on all rules
     * @private
     * @param {Record<string, VersionData>} versions - Version data map
     * @param {string} packageName - Package name
     * @returns {FilterResult} Result object
     */
    private _filterVersions(versions: Record<string, VersionData>, packageName: string): FilterResult {
        const filteredVersions: Record<string, VersionData> = {};
        const blockedVersions: string[] = [];
        const fallbacksApplied: Array<{ original: string; fallback: string }> = [];

        for (const [ version, versionData ] of Object.entries(versions)) {
            const versionKey = `${packageName}@${version}`;

            // Check exact blocked versions
            if (this.securityRules.blockedVersions.includes(versionKey)) {
                this.logger.warn(`[Security Filter] Filtering out blocked version: ${versionKey}`);
                blockedVersions.push(version);
                continue;
            }

            // Check version range rules
            const rangeRule = this._getVersionRangeRule(packageName, version);

            if (rangeRule) {
                if (rangeRule.strategy === 'block') {
                    // Block strategy: remove version
                    this.logger.warn(`[Security Filter] Blocking ${versionKey} (range: ${rangeRule.range})`);
                    blockedVersions.push(version);
                    continue;
                } else if (rangeRule.strategy === 'fallback' && rangeRule.fallbackVersion) {
                    // Fallback strategy: redirect to safe version
                    this.logger.info(`[Security Filter] Applying fallback for ${versionKey} -> ${rangeRule.fallbackVersion}`);

                    // Check if fallback version exists in original versions
                    if (versions[rangeRule.fallbackVersion]) {
                        filteredVersions[version] = {
                            ...versions[rangeRule.fallbackVersion],
                            version: version, // Keep original version number for compatibility
                            _fallback: true,
                            _fallbackFrom: rangeRule.fallbackVersion,
                            _fallbackReason: rangeRule.reason || 'Version blocked by security rule'
                        };
                        fallbacksApplied.push({ original: version, fallback: rangeRule.fallbackVersion });
                    } else {
                        this.logger.warn(`[Security Filter] Fallback version ${rangeRule.fallbackVersion} not found for ${packageName}, blocking instead`);
                        blockedVersions.push(version);
                    }
                    continue;
                }
            }

            // Version passed all checks
            filteredVersions[version] = versionData;
        }

        return { versions: filteredVersions, blockedVersions, fallbacksApplied };
    }

    /**
     * Update dist-tags to point to valid versions
     * @private
     * @param {Record<string, string>} distTags - Distribution tags
     * @param {Record<string, VersionData>} availableVersions - Available versions
     * @returns {Record<string, string>} Updated dist-tags
     */
    private _updateDistTags(distTags: Record<string, string>, availableVersions: Record<string, VersionData>): Record<string, string> {
        const updatedTags: Record<string, string> = {};

        for (const [ tag, version ] of Object.entries(distTags)) {
            if (availableVersions[version]) {
                updatedTags[tag] = version;
            } else {
                // Find latest available version as fallback for tags
                const availableVersionsList = Object.keys(availableVersions).sort(semver.rcompare);
                if (availableVersionsList.length > 0) {
                    updatedTags[tag] = availableVersionsList[0];
                    this.logger.info(`[Security Filter] Updated dist-tag "${tag}" from ${version} to ${availableVersionsList[0]}`);
                }
            }
        }

        return updatedTags;
    }

    /**
     * Get list of blocked versions for a package
     * @private
     * @param {string} packageName - Package name
     * @returns {string[]} List of blocked version ranges
     */
    private _getBlockedVersionsList(packageName: string): string[] {
        return this.securityRules.versionRangeRules
            .filter(rule => rule.package === packageName && rule.strategy === 'block')
            .map(rule => rule.range);
    }

    /**
     * Get list of fallback version mappings for a package
     * @private
     * @param {string} packageName - Package name
     * @returns {string[]} List of fallback descriptions
     */
    private _getFallbackVersionsList(packageName: string): string[] {
        return this.securityRules.versionRangeRules
            .filter(rule => rule.package === packageName && rule.strategy === 'fallback')
            .map(rule => `${rule.range} -> ${rule.fallbackVersion}`);
    }

    /**
     * Validate package metadata
     * @private
     * @param {string} packageName - Package name
     * @param {string} version - Package version
     * @returns {boolean} True if valid
     */
    private _validateMetadata(packageName: string): boolean {
        // Basic package name validation
        if (!packageName || packageName.length === 0) {
            return false;
        }

        // Check for dangerous characters
        const dangerousChars = /[<>:"\/\\|?*\x00-\x1f]/;
        if (dangerousChars.test(packageName)) {
            this.logger.warn(`[Security Filter] Dangerous characters in package name: ${packageName}`);
            return false;
        }

        return true;
    }

    /**
     * Create a blocked package response
     * @private
     * @param {string} packageName - Package name
     * @param {string} reason - Reason for blocking
     * @returns {Package} Blocked package metadata
     */
    private _createBlockedResponse(packageName: string, reason: string): Package {
        return {
            name: packageName,
            versions: {},
            'dist-tags': {},
            _blocked: true,
            _blockReason: reason,
            time: {},
            _id: packageName,
            readme: '',
            _rev: '',
            _attachments: {}
        } as Package & { _blocked: boolean; _blockReason: string };
    }
}
