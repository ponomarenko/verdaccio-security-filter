import { Config, Version } from '@verdaccio/types';

export interface VersionRangeRule {
    package: string;
    range: string;
    strategy: 'block' | 'fallback';
    fallbackVersion?: string;
    reason?: string;
}

export interface CVECheckConfig {
    enabled: boolean;
    databases: ('osv' | 'snyk' | 'github')[];
    severity: ('low' | 'medium' | 'high' | 'critical')[];
    autoBlock: boolean;
    updateInterval?: number; // hours
    cacheDir?: string;
}

export interface WhitelistConfig {
    packages: string[];
    patterns: string[];
    versions?: Record<string, string>;
    autoApprove?: {
        minDownloads?: number;
        minStars?: number;
        verifiedPublisher?: boolean;
    };
}

export interface LicenseConfig {
    allowed: string[];
    blocked: string[];
    requireLicense: boolean;
}

export interface LoggerConfig {
    level: 'trace' | 'debug' | 'info' | 'warn' | 'error';
    enabled: boolean;
    includeTimestamp?: boolean;
}

export interface MetricsConfig {
    enabled: boolean;
    output?: 'stdout' | 'file';
    filePath?: string;
}

export interface PackageAgeConfig {
    enabled: boolean;
    minPackageAgeDays: number; // Minimum age in days for a package to be accepted
    minVersionAgeDays?: number; // Minimum age in days for a specific version to be accepted
    warnOnly?: boolean; // Only warn instead of blocking
}

export interface AuthorFilterConfig {
    enabled: boolean;
    blockedAuthors?: string[]; // List of author names to block
    blockedAuthorPatterns?: string[]; // Regex patterns for author names
    blockedEmails?: string[]; // List of author email addresses to block
    blockedEmailPatterns?: string[]; // Regex patterns for author emails
    blockedEmailDomains?: string[]; // List of email domains to block (e.g., '.ru', '@yandex.ru')
    blockedRegions?: string[]; // Region codes to block based on email domain (e.g., 'ru', 'cn')
    requireVerifiedEmail?: boolean; // Require verified email from npm registry
    warnOnly?: boolean; // Only warn instead of blocking
}

export interface SecurityConfig extends Config {
    // Existing fields
    blockedVersions?: string[];
    blockedPatterns?: string[];
    minPackageSize?: number;
    maxPackageSize?: number;
    allowedScopes?: string[];
    blockedScopes?: string[];
    enforceChecksum?: boolean;
    versionRangeRules?: VersionRangeRule[];

    // Phase 2: New features
    mode?: 'blacklist' | 'whitelist';
    whitelist?: WhitelistConfig;
    licenses?: LicenseConfig;
    cveCheck?: CVECheckConfig;
    logger?: LoggerConfig;
    metrics?: MetricsConfig;
    packageAge?: PackageAgeConfig;
    authorFilter?: AuthorFilterConfig;

    // Error handling strategy
    errorHandling?: {
        onFilterError?: 'fail-open' | 'fail-closed';
        onCveCheckError?: 'fail-open' | 'fail-closed';
        onLicenseCheckError?: 'fail-open' | 'fail-closed';
    };
}

export interface SecurityRules {
    blockedVersions: string[];
    blockedPatterns: string[];
    minPackageSize: number;
    maxPackageSize: number;
    allowedScopes: string[];
    blockedScopes: string[];
    enforceChecksum: boolean;
    versionRangeRules: VersionRangeRule[];
}

export interface VersionData extends Version {
    /** Internal flag for fallback versions */
    _fallback?: boolean;

    /** Original version this is falling back from */
    _fallbackFrom?: string;

    /** Reason for fallback */
    _fallbackReason?: string;
}

export interface FilterResult {
    versions: Record<string, VersionData>;
    blockedVersions: string[];
    fallbacksApplied: Array<{ original: string; fallback: string }>;
}

export interface CVEVulnerability {
    id: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    summary: string;
    affectedVersions: string[];
    fixedVersion?: string;
    publishedDate: string;
    source: string;
}

export interface CVECheckResult {
    package: string;
    version: string;
    vulnerabilities: CVEVulnerability[];
    isVulnerable: boolean;
    checkedAt: string;
}

export interface MetricsData {
    timestamp: string;
    event: 'block' | 'fallback' | 'publish_rejected' | 'cve_detected' | 'license_blocked' | 'package_too_new' | 'author_blocked';
    packageName: string;
    version?: string;
    reason: string;
    metadata?: Record<string, any>;
}

export interface AuthorInfo {
    name?: string;
    email?: string;
    url?: string;
}

export interface AuthorCheckResult {
    allowed: boolean;
    reason?: string;
    blockedBy?: 'name' | 'email' | 'domain' | 'region';
    authorInfo?: AuthorInfo;
}
