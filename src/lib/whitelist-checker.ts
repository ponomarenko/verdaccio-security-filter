import * as semver from 'semver';
import { WhitelistConfig } from '../types';
import { CheckerLog } from './logger';

/**
 * Whitelist checker for package validation
 */
export class WhitelistChecker {
    private config: WhitelistConfig;
    private regexes = new Map<string, RegExp | null>();

    constructor(config?: WhitelistConfig, private readonly log: CheckerLog = console) {
        this.config = {
            packages: config?.packages || [],
            patterns: config?.patterns || [],
            versions: config?.versions || {},
        };
    }

    /**
     * Check if a package is whitelisted
     */
    isWhitelisted(packageName: string, version?: string): { allowed: boolean; reason?: string } {
        // Check exact package name match
        if (this.config.packages.includes(packageName)) {
            // If version is specified, check version constraint
            if (version && this.config.versions && packageName in this.config.versions) {
                const versionRange = this.config.versions[packageName];
                if (!semver.satisfies(version, versionRange)) {
                    return {
                        allowed: false,
                        reason: `Version ${version} does not satisfy whitelist constraint ${versionRange}`,
                    };
                }
            }
            return { allowed: true };
        }

        // Check pattern match
        if (this.matchesPattern(packageName)) {
            return { allowed: true };
        }

        // Not in whitelist
        return {
            allowed: false,
            reason: 'Package is not in whitelist',
        };
    }

    /**
     * Check if package name matches any whitelist pattern
     */
    private matchesPattern(packageName: string): boolean {
        return this.config.patterns.some(pattern => this.compile(pattern)?.test(packageName));
    }

    /**
     * Compile a pattern once; an invalid one is reported once and never matches.
     */
    private compile(pattern: string): RegExp | null {
        let regex = this.regexes.get(pattern);
        if (regex === undefined) {
            try {
                regex = new RegExp(pattern);
            } catch {
                this.log.error(`[Whitelist] Invalid pattern: ${pattern}`);
                regex = null;
            }
            this.regexes.set(pattern, regex);
        }
        return regex;
    }

    /**
     * Add package to whitelist
     */
    addPackage(packageName: string, versionRange?: string): void {
        if (!this.config.packages.includes(packageName)) {
            this.config.packages.push(packageName);
        }

        if (versionRange) {
            this.config.versions = this.config.versions || {};
            this.config.versions[packageName] = versionRange;
        }
    }

    /**
     * Remove package from whitelist
     */
    removePackage(packageName: string): void {
        const index = this.config.packages.indexOf(packageName);
        if (index > -1) {
            this.config.packages.splice(index, 1);
        }

        if (this.config.versions && packageName in this.config.versions) {
            delete this.config.versions[packageName];
        }
    }

    /**
     * Add pattern to whitelist
     */
    addPattern(pattern: string): void {
        if (!this.config.patterns.includes(pattern)) {
            this.config.patterns.push(pattern);
        }
    }

    /**
     * Get whitelist summary
     */
    getSummary(): {
        totalPackages: number;
        totalPatterns: number;
    } {
        return {
            totalPackages: this.config.packages.length,
            totalPatterns: this.config.patterns.length,
        };
    }
}
