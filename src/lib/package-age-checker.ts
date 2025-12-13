import { PackageAgeConfig } from '../types';
import { Package } from '@verdaccio/types';

/**
 * Package age checker to protect against newly created malicious packages
 */
export class PackageAgeChecker {
    private config: PackageAgeConfig;

    constructor(config?: PackageAgeConfig) {
        this.config = {
            enabled: config?.enabled ?? false,
            minPackageAgeDays: config?.minPackageAgeDays ?? 0,
            minVersionAgeDays: config?.minVersionAgeDays,
            warnOnly: config?.warnOnly ?? false,
        };
    }

    /**
     * Check if a package is old enough to be trusted
     */
    checkPackageAge(
        packageData: Package
    ): { allowed: boolean; reason?: string; ageDays?: number; warnOnly?: boolean } {
        if (!this.config.enabled) {
            return { allowed: true };
        }

        // Get package creation date from time field
        const createdDate = this.getPackageCreationDate(packageData);
        if (!createdDate) {
            // If we can't determine creation date, allow but warn
            return {
                allowed: true,
                reason: 'Cannot determine package creation date',
            };
        }

        const ageDays = this.calculateAgeDays(createdDate);

        if (ageDays < this.config.minPackageAgeDays) {
            const warnOnlyValue = this.config.warnOnly || false;
            return {
                allowed: warnOnlyValue,
                reason: `Package is only ${ageDays} days old (minimum: ${this.config.minPackageAgeDays} days)`,
                ageDays,
                warnOnly: warnOnlyValue,
            };
        }

        return { allowed: true, ageDays };
    }

    /**
     * Check if a specific version is old enough to be trusted
     */
    checkVersionAge(
        packageData: Package,
        version: string
    ): { allowed: boolean; reason?: string; ageDays?: number; warnOnly?: boolean } {
        if (!this.config.enabled || !this.config.minVersionAgeDays) {
            return { allowed: true };
        }

        // Get version publish date from time field
        const versionDate = this.getVersionPublishDate(packageData, version);
        if (!versionDate) {
            // If we can't determine version date, allow but warn
            return {
                allowed: true,
                reason: `Cannot determine version ${version} publish date`,
            };
        }

        const ageDays = this.calculateAgeDays(versionDate);

        if (ageDays < this.config.minVersionAgeDays) {
            const warnOnlyValue = this.config.warnOnly || false;
            return {
                allowed: warnOnlyValue,
                reason: `Version ${version} is only ${ageDays} days old (minimum: ${this.config.minVersionAgeDays} days)`,
                ageDays,
                warnOnly: warnOnlyValue,
            };
        }

        return { allowed: true, ageDays };
    }

    /**
     * Get package creation date from time field
     * The 'created' field in package.time represents when the package was first published
     */
    private getPackageCreationDate(packageData: Package): Date | null {
        if (!packageData.time) {
            return null;
        }

        // Try to get 'created' field first
        if ('created' in packageData.time) {
            const created = packageData.time.created;
            if (typeof created === 'string') {
                return new Date(created);
            }
        }

        // Fallback: find the oldest version
        const versions = Object.keys(packageData.time).filter(
            key => key !== 'modified' && key !== 'created'
        );

        if (versions.length === 0) {
            return null;
        }

        const dates = versions
            .map(v => {
                const timeValue = packageData.time![v];
                return typeof timeValue === 'string' ? new Date(timeValue) : null;
            })
            .filter((d): d is Date => d !== null);

        if (dates.length === 0) {
            return null;
        }

        // Return the oldest date
        return new Date(Math.min(...dates.map(d => d.getTime())));
    }

    /**
     * Get version publish date from time field
     */
    private getVersionPublishDate(packageData: Package, version: string): Date | null {
        if (!packageData.time || !(version in packageData.time)) {
            return null;
        }

        const timeValue = packageData.time[version];
        if (typeof timeValue === 'string') {
            return new Date(timeValue);
        }

        return null;
    }

    /**
     * Calculate age in days from a date
     */
    private calculateAgeDays(date: Date): number {
        const now = new Date();
        const diffMs = now.getTime() - date.getTime();
        return Math.floor(diffMs / (1000 * 60 * 60 * 24));
    }

    /**
     * Get summary of configuration
     */
    getSummary(): {
        enabled: boolean;
        minPackageAgeDays: number;
        minVersionAgeDays?: number;
        warnOnly: boolean;
    } {
        return {
            enabled: this.config.enabled,
            minPackageAgeDays: this.config.minPackageAgeDays,
            minVersionAgeDays: this.config.minVersionAgeDays,
            warnOnly: this.config.warnOnly || false,
        };
    }
}
