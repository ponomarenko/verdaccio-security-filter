import { LicenseConfig } from '../types';
import { Version } from '@verdaccio/types';

/**
 * License checker for validating package licenses
 */
export class LicenseChecker {
    private config: LicenseConfig;

    constructor(config?: LicenseConfig) {
        this.config = {
            allowed: config?.allowed || [],
            blocked: config?.blocked || [],
            requireLicense: config?.requireLicense !== false,
        };
    }

    /**
     * Check if a package version's license is allowed
     */
    checkLicense(versionData: Version): { allowed: boolean; reason?: string; license?: string } {
        const license = this.extractLicense(versionData);

        // Check if license is missing
        if (!license || license === 'UNLICENSED' || license === '') {
            if (this.config.requireLicense) {
                return {
                    allowed: false,
                    reason: 'Package does not specify a license',
                    license: license || 'none',
                };
            }
            return { allowed: true };
        }

        // Check blocked list
        if (this.isLicenseBlocked(license)) {
            return {
                allowed: false,
                reason: `License '${license}' is in blocked list`,
                license,
            };
        }

        // Check allowed list (if specified)
        if (this.config.allowed.length > 0 && !this.isLicenseAllowed(license)) {
            return {
                allowed: false,
                reason: `License '${license}' is not in allowed list`,
                license,
            };
        }

        return { allowed: true, license };
    }

    /**
     * Extract license from version data
     */
    private extractLicense(versionData: Version): string | null {
        if (!versionData.license) {
            return null;
        }

        // Handle string license
        if (typeof versionData.license === 'string') {
            return versionData.license;
        }

        // Handle SPDX license object
        if (typeof versionData.license === 'object' && 'type' in versionData.license) {
            return (versionData.license as any).type;
        }

        return null;
    }

    /**
     * Check if license is blocked
     */
    private isLicenseBlocked(license: string): boolean {
        return this.config.blocked.some(blocked => {
            // Exact match
            if (blocked === license) {
                return true;
            }

            // Handle SPDX expressions (e.g., "MIT OR Apache-2.0")
            const licenseTokens = license.split(/\s+(?:OR|AND)\s+/i);
            return licenseTokens.some(token => token.trim() === blocked);
        });
    }

    /**
     * Check if license is allowed
     */
    private isLicenseAllowed(license: string): boolean {
        return this.config.allowed.some(allowed => {
            // Exact match
            if (allowed === license) {
                return true;
            }

            // Handle SPDX expressions (e.g., "MIT OR Apache-2.0")
            const licenseTokens = license.split(/\s+(?:OR|AND)\s+/i);
            return licenseTokens.some(token => token.trim() === allowed);
        });
    }

    /**
     * Get common open source licenses
     */
    static getCommonOpenSourceLicenses(): string[] {
        return [
            'MIT',
            'Apache-2.0',
            'BSD-2-Clause',
            'BSD-3-Clause',
            'ISC',
            '0BSD',
            'CC0-1.0',
            'Unlicense',
        ];
    }

    /**
     * Get common copyleft licenses
     */
    static getCopyleftLicenses(): string[] {
        return [
            'GPL-2.0',
            'GPL-3.0',
            'AGPL-3.0',
            'LGPL-2.1',
            'LGPL-3.0',
            'MPL-2.0',
            'EPL-2.0',
        ];
    }
}
