import { Config, Version } from '@verdaccio/types';

export interface VersionRangeRule {
    package: string;
    range: string;
    strategy: 'block' | 'fallback';
    fallbackVersion?: string;
    reason?: string;
}

export interface SecurityConfig extends Config {
    blockedVersions?: string[];
    blockedPatterns?: string[];
    minPackageSize?: number;
    maxPackageSize?: number;
    allowedScopes?: string[];
    blockedScopes?: string[];
    enforceChecksum?: boolean;
    versionRangeRules?: VersionRangeRule[];
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
