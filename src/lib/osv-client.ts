import * as semver from 'semver';
import { CVEVulnerability } from '../types';

type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';

interface OSVMetadata extends Record<string, unknown> {
    severity?: unknown;
}

interface OSVPackage {
    name?: string;
    ecosystem?: string;
    purl?: string;
}

interface OSVSeverity {
    type?: string;
    score?: string;
}

interface OSVRangeEvent {
    introduced?: string;
    fixed?: string;
    last_affected?: string;
    limit?: string;
}

interface OSVRange {
    type?: string;
    events?: OSVRangeEvent[];
}

interface OSVAffected {
    package?: OSVPackage;
    ranges?: OSVRange[];
    versions?: string[];
    severity?: OSVSeverity[];
    ecosystem_specific?: OSVMetadata;
    database_specific?: OSVMetadata;
}

// https://github.com/ossf/osv-schema/blob/main/validation/schema.json
interface OSVVulnerability {
    id: string;
    summary?: string;
    details?: string;
    severity?: OSVSeverity[];
    affected?: OSVAffected[];
    published?: string;
    database_specific?: OSVMetadata;
}

interface OSVQueryResponse {
    vulns?: OSVVulnerability[];
    next_page_token?: string;
}

export interface OSVCachedVulnerability extends CVEVulnerability {
    affected: OSVAffected[];
}

interface OSVVersionMatch {
    introducedVersion?: string;
    fixedVersion?: string;
}

interface OSVClientOptions {
    ecosystem: string;
    fetchImpl: typeof fetch;
    maxRetries: number;
    retryDelayMs: number;
    timeoutMs: number;
}

const OSV_QUERY_URL = 'https://api.osv.dev/v1/query';

interface OSVClientLogger {
    debug(message: string, ...args: unknown[]): void;
    warn(message: string, ...args: unknown[]): void;
    error(message: string, ...args: unknown[]): void;
}

const DEFAULT_OSV_CLIENT_LOGGER: OSVClientLogger = {
    debug: console.debug,
    warn: console.warn,
    error: console.error,
};

const formatPageToken = (pageToken: string | undefined): string => {
    if (!pageToken) return 'none';
    return pageToken.length > 16 ? `${pageToken.slice(0, 16)}...` : pageToken;
};

export class OSVClient {
    private readonly options: OSVClientOptions;
    private readonly logger: OSVClientLogger;

    constructor(
        options: Partial<OSVClientOptions> = {},
        logger: OSVClientLogger = DEFAULT_OSV_CLIENT_LOGGER,
    ) {
        const defaultOptions: OSVClientOptions = {
            maxRetries: 3,
            retryDelayMs: 1000,
            timeoutMs: 10000,
            fetchImpl: fetch,
            ecosystem: 'npm',
        };
        this.options = {
            ...defaultOptions,
            ...options,
        };
        this.logger = logger;
    }

    async fetchVulnerabilities(packageName: string): Promise<OSVCachedVulnerability[]> {
        const vulnerabilities: OSVCachedVulnerability[] = [];
        const seenPageTokens = new Set<string>();
        let pageToken: string | undefined;
        let pageNumber = 1;

        this.debug(`Fetching vulnerabilities for ${this.options.ecosystem}/${packageName}`);

        do {
            const data = await this.fetchPage(packageName, pageToken, pageNumber);
            const pageVulnerabilityCount = data.vulns?.length || 0;
            let normalizedPageVulnerabilityCount = 0;

            for (const vuln of (data.vulns || [])) {
                const normalized = this.normalizeOSVVulnerability(vuln, packageName);
                if (normalized) {
                    vulnerabilities.push(normalized);
                    normalizedPageVulnerabilityCount++;
                }
            }

            const nextPageToken = data.next_page_token;
            this.debug(`Page ${pageNumber} returned ${pageVulnerabilityCount} advisories, ${normalizedPageVulnerabilityCount} matching ${packageName}, next page token: ${formatPageToken(nextPageToken)}`);
            if (!nextPageToken) break;

            if (seenPageTokens.has(nextPageToken)) {
                this.warn(`OSV returned duplicate page token for ${packageName}, stopping pagination`);
                break;
            }

            seenPageTokens.add(nextPageToken);
            pageToken = nextPageToken;
            pageNumber++;
        } while (pageToken);

        this.debug(`Finished fetching ${this.options.ecosystem}/${packageName}: ${vulnerabilities.length} matching advisories across ${pageNumber} page(s)`);

        return vulnerabilities;
    }

    matchVulnerabilityForVersion(
        vulnerability: OSVCachedVulnerability,
        packageName: string,
        version: string,
    ): CVEVulnerability | undefined {
        for (const affected of vulnerability.affected) {
            if (!this.isAffectedPackageEntry(affected, packageName)) {
                continue;
            }

            const match = this.matchOSVAffectedVersion(version, affected);
            if (match) {
                return {
                    id: vulnerability.id,
                    severity: vulnerability.severity,
                    summary: vulnerability.summary,
                    affectedVersions: vulnerability.affectedVersions,
                    introducedVersion: match.introducedVersion,
                    fixedVersion: match.fixedVersion,
                    publishedDate: vulnerability.publishedDate,
                    source: vulnerability.source,
                };
            }
        }

        return undefined;
    }

    private async fetchPage(
        packageName: string,
        pageToken: string | undefined,
        pageNumber: number,
    ): Promise<OSVQueryResponse> {
        const {
            maxRetries,
            retryDelayMs,
            timeoutMs,
            fetchImpl,
            ecosystem,
        } = this.options;

        for (let attempt = 1; attempt <= maxRetries; attempt++) {
            let timeoutId: NodeJS.Timeout | undefined;
            try {
                const controller = new AbortController();
                timeoutId = setTimeout(() => controller.abort(), timeoutMs);

                // https://google.github.io/osv.dev/post-v1-query/
                this.debug(`Fetching page ${pageNumber} for ${ecosystem}/${packageName} (attempt ${attempt}/${maxRetries}, page token: ${formatPageToken(pageToken)})`);
                const response = await fetchImpl(OSV_QUERY_URL, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        package: {
                            name: packageName,
                            ecosystem,
                        },
                        ...(pageToken ? { page_token: pageToken } : {}),
                    }),
                    signal: controller.signal,
                });
                this.debug(`Received HTTP ${response.status} for page ${pageNumber} of ${ecosystem}/${packageName}`);

                if (!response.ok) {
                    if (response.status === 429 && attempt < maxRetries) {
                        const waitTime = retryDelayMs * Math.pow(2, attempt - 1);
                        this.warn(`Rate limited, retrying in ${waitTime}ms (attempt ${attempt}/${maxRetries})`);
                        await sleep(waitTime);
                        continue;
                    }
                    throw new Error(`OSV API returned ${response.status}`);
                }

                return await response.json();
            } catch (error) {
                const message = error instanceof Error ? error.message : String(error);

                if (attempt === maxRetries) {
                    this.error(`OSV API error after ${maxRetries} attempts:`, message);
                    throw error instanceof Error ? error : new Error(message);
                }

                if (error instanceof Error && error.name === 'AbortError') {
                    this.warn(`Request timeout, retrying (attempt ${attempt}/${maxRetries})`);
                } else {
                    this.warn(`Request failed, retrying (attempt ${attempt}/${maxRetries}):`, message);
                }

                await sleep(retryDelayMs * attempt);
            } finally {
                if (timeoutId !== undefined) {
                    clearTimeout(timeoutId);
                }
            }
        }

        throw new Error('OSV API request failed');
    }

    normalizeOSVVulnerability(
        vuln: OSVVulnerability,
        packageName: string,
    ): OSVCachedVulnerability | undefined {
        const affected = (vuln.affected || []).filter(affectedEntry =>
            this.isAffectedPackageEntry(affectedEntry, packageName)
        );

        if (affected.length === 0) {
            return undefined;
        }

        const affectedVersions = affected
            .flatMap(affectedEntry => affectedEntry.versions || [])
            .filter((version, index, versions) => versions.indexOf(version) === index);

        return {
            id: vuln.id,
            severity: this.mapOSVSeverity(
                vuln.severity,
                affected.map(affectedEntry => affectedEntry.severity),
                affected.map(affectedEntry => affectedEntry.ecosystem_specific?.severity),
                affected.map(affectedEntry => affectedEntry.database_specific?.severity),
                vuln.database_specific?.severity
            ),
            summary: vuln.summary || vuln.details || 'No description available',
            affectedVersions,
            introducedVersion: this.findFirstIntroducedVersion(affected),
            fixedVersion: this.findFirstFixedVersion(affected),
            publishedDate: vuln.published || new Date().toISOString(),
            source: 'osv',
            affected,
        };
    }

    mapOSVSeverity(...severityCandidates: unknown[]): SeverityLevel {
        for (const severityCandidate of severityCandidates) {
            if (!severityCandidate) {
                continue;
            }

            const severity = this.mapSeverityCandidate(severityCandidate);
            if (severity) {
                return severity;
            }
        }

        return 'medium';
    }

    matchOSVRange(version: string, range: OSVRange): OSVVersionMatch | undefined {
        const rangeType = range.type?.toUpperCase();
        if (rangeType !== 'SEMVER' && rangeType !== 'ECOSYSTEM') {
            return undefined;
        }

        let introducedVersion: string | undefined;
        let intervalOpen = false;

        for (const event of range.events || []) {
            if (event.introduced !== undefined) {
                introducedVersion = event.introduced;
                intervalOpen = true;
                continue;
            }

            if (!intervalOpen) continue;

            if (event.fixed !== undefined) {
                if (this.isVersionWithinInterval(version, introducedVersion, event.fixed, false)) {
                    return { introducedVersion, fixedVersion: event.fixed };
                }
                intervalOpen = false;
                introducedVersion = undefined;
                continue;
            }

            if (event.last_affected !== undefined) {
                if (this.isVersionWithinInterval(version, introducedVersion, event.last_affected, true)) {
                    return { introducedVersion };
                }
                intervalOpen = false;
                introducedVersion = undefined;
                continue;
            }

            if (event.limit !== undefined) {
                if (this.isVersionWithinInterval(version, introducedVersion, event.limit, false)) {
                    return { introducedVersion };
                }
                intervalOpen = false;
                introducedVersion = undefined;
            }
        }

        if (intervalOpen && this.isVersionGreaterThanOrEqual(version, introducedVersion)) {
            return { introducedVersion };
        }

        return undefined;
    }

    private isAffectedPackageEntry(
        affected: OSVAffected,
        packageName: string,
    ): boolean {
        if (!affected.package) {
            return true;
        }

        if (affected.package.ecosystem && affected.package.ecosystem !== this.options.ecosystem) {
            return false;
        }

        return !affected.package.name || affected.package.name === packageName;
    }

    private matchOSVAffectedVersion(version: string, affected: OSVAffected): OSVVersionMatch | undefined {
        for (const range of affected.ranges || []) {
            const match = this.matchOSVRange(version, range);
            if (match) {
                return match;
            }
        }

        if (affected.versions?.includes(version)) {
            return {
                introducedVersion: this.findFirstIntroducedVersion([affected]),
                fixedVersion: this.findFirstFixedVersion([affected]),
            };
        }

        return undefined;
    }

    private findFirstIntroducedVersion(affected: OSVAffected[]): string | undefined {
        for (const affectedEntry of affected) {
            for (const range of affectedEntry.ranges || []) {
                const introduced = range.events?.find(event => event.introduced !== undefined)?.introduced;
                if (introduced !== undefined) {
                    return introduced;
                }
            }
        }

        return undefined;
    }

    private findFirstFixedVersion(affected: OSVAffected[]): string | undefined {
        for (const affectedEntry of affected) {
            for (const range of affectedEntry.ranges || []) {
                const fixed = range.events?.find(event => event.fixed !== undefined)?.fixed;
                if (fixed !== undefined) {
                    return fixed;
                }
            }
        }

        return undefined;
    }

    private mapSeverityCandidate(severityCandidate: unknown): SeverityLevel | undefined {
        const severityMapping: Record<string, SeverityLevel> = {
            critical: "critical",
            high: "high",
            moderate: "medium",
            medium: "medium",
            low: "low",
        };

        if (typeof severityCandidate === 'string') {
            return severityMapping[severityCandidate.toLowerCase()];
        }

        if (Array.isArray(severityCandidate)) {
            for (const item of severityCandidate) {
                const severity = this.mapSeverityCandidate(item);
                if (severity) {
                    return severity;
                }
            }
            return undefined;
        }

        if (typeof severityCandidate !== 'object' || severityCandidate === null) {
            return undefined;
        }

        if ('severity' in severityCandidate && typeof severityCandidate.severity === 'string') {
            return severityMapping[severityCandidate.severity.toLowerCase()];
        }

        if ('score' in severityCandidate && (typeof severityCandidate.score === 'string' || typeof severityCandidate.score === 'number')) {
            const score = Number(severityCandidate.score);
            if (!Number.isNaN(score)) {
                if (score >= 9.0) return 'critical';
                if (score >= 7.0) return 'high';
                if (score >= 4.0) return 'medium';
                return 'low';
            }
        }

        return undefined;
    }

    private isVersionWithinInterval(
        version: string,
        introducedVersion: string | undefined,
        endVersion: string,
        endInclusive: boolean
    ): boolean {
        const isVersionLessThanOrEqual = (version: string, boundary: string): boolean => {
            const comparison = this.compareVersions(version, boundary);
            return comparison !== undefined && comparison <= 0;
        };

        const isVersionLessThan = (version: string, boundary: string): boolean => {
            const comparison = this.compareVersions(version, boundary);
            return comparison !== undefined && comparison < 0;
        };

        return this.isVersionGreaterThanOrEqual(version, introducedVersion)
            && (endInclusive
                ? isVersionLessThanOrEqual(version, endVersion)
                : isVersionLessThan(version, endVersion));
    }

    private isVersionGreaterThanOrEqual(version: string, boundary: string | undefined): boolean {
        if (!boundary || boundary === '0') {
            return true;
        }

        const comparison = this.compareVersions(version, boundary);
        return comparison !== undefined && comparison >= 0;
    }

    private compareVersions(version: string, boundary: string): number | undefined {
        const validVersion = semver.valid(version, true);
        const validBoundary = semver.valid(boundary, true);

        if (!validVersion || !validBoundary) {
            return version === boundary ? 0 : undefined;
        }

        return semver.compare(validVersion, validBoundary);
    }

    private debug(message: string, ...args: unknown[]): void {
        this.logger.debug(`[OSV Client] ${message}`, ...args);
    }

    private warn(message: string, ...args: unknown[]): void {
        this.logger.warn(`[OSV Client] ${message}`, ...args);
    }

    private error(message: string, ...args: unknown[]): void {
        this.logger.error(`[OSV Client] ${message}`, ...args);
    }
}

const sleep = (ms: number): Promise<void> => {
    return new Promise(resolve => setTimeout(resolve, ms));
};
