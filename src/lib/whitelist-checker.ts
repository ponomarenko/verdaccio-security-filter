import * as semver from 'semver';
import { WhitelistConfig } from '../types';

/**
 * Whitelist checker for package validation
 */
export class WhitelistChecker {
    private config: WhitelistConfig;

    constructor(config?: WhitelistConfig) {
        this.config = {
            packages: config?.packages || [],
            patterns: config?.patterns || [],
            versions: config?.versions || {},
            autoApprove: config?.autoApprove,
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
        return this.config.patterns.some(pattern => {
            try {
                const regex = new RegExp(pattern);
                return regex.test(packageName);
            } catch {
                console.error(`[Whitelist] Invalid pattern: ${pattern}`);
                return false;
            }
        });
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
     * Check if package meets auto-approve criteria
     * Note: This is a placeholder. Real implementation would require
     * integration with npm registry API to fetch download stats, etc.
     */
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async meetsAutoApproveCriteria(_packageName: string): Promise<{ approved: boolean; reason?: string }> {
        if (!this.config.autoApprove) {
            return { approved: false, reason: 'Auto-approve not configured' };
        }

        // Placeholder for npm registry API integration
        // In a real implementation, you would:
        // 1. Fetch package info from npm registry
        // 2. Check weekly downloads against minDownloads
        // 3. Check GitHub stars against minStars
        // 4. Check if publisher is verified

        return {
            approved: false,
            reason: 'Auto-approve requires npm registry API integration (not implemented)',
        };
    }

    /**
     * Get whitelist summary
     */
    getSummary(): {
        totalPackages: number;
        totalPatterns: number;
        hasAutoApprove: boolean;
    } {
        return {
            totalPackages: this.config.packages.length,
            totalPatterns: this.config.patterns.length,
            hasAutoApprove: !!this.config.autoApprove,
        };
    }
}
