import { Version } from '@verdaccio/types';
import { AuthorFilterConfig, AuthorCheckResult, AuthorInfo } from '../types';

/**
 * Region to TLD mapping for email domain filtering
 */
const REGION_DOMAINS: Record<string, string[]> = {
    'ru': ['.ru', 'yandex.ru', 'mail.ru', 'rambler.ru', 'ya.ru', 'bk.ru', 'list.ru'],
    'cn': ['.cn', 'qq.com', '163.com', '126.com', 'sina.com', 'sohu.com'],
    'by': ['.by', 'tut.by', 'mail.by'],
    'kp': ['.kp'], // North Korea
    'ir': ['.ir'], // Iran
    'sy': ['.sy'], // Syria
    'cu': ['.cu'], // Cuba
    'sd': ['.sd'], // Sudan
};

/**
 * AuthorChecker validates package authors and maintainers
 * against configured security policies.
 */
export class AuthorChecker {
    private readonly config?: AuthorFilterConfig;
    private readonly blockedAuthors: Set<string>;
    private readonly blockedAuthorPatterns: RegExp[];
    private readonly blockedEmails: Set<string>;
    private readonly blockedEmailPatterns: RegExp[];
    private readonly blockedEmailDomains: Set<string>;
    private readonly regionDomainMap: Map<string, Set<string>>;

    constructor(config?: AuthorFilterConfig) {
        this.config = config;

        this.blockedAuthors = new Set(
            (config?.blockedAuthors || []).map(a => a.toLowerCase().trim())
        );

        this.blockedAuthorPatterns = (config?.blockedAuthorPatterns || [])
            .map(pattern => new RegExp(pattern, 'i'));

        this.blockedEmails = new Set(
            (config?.blockedEmails || []).map(e => e.toLowerCase().trim())
        );

        this.blockedEmailPatterns = (config?.blockedEmailPatterns || [])
            .map(pattern => new RegExp(pattern, 'i'));

        this.blockedEmailDomains = new Set(
            (config?.blockedEmailDomains || []).map(d => d.toLowerCase().trim())
        );

        this.regionDomainMap = new Map();
        (config?.blockedRegions || []).forEach(region => {
            const domains = REGION_DOMAINS[region.toLowerCase()] || [];
            this.regionDomainMap.set(region.toLowerCase(), new Set(domains));
        });
    }

    /**
     * Check if package author/maintainer is allowed
     */
    checkAuthor(versionData: Version): AuthorCheckResult {
        if (!this.config?.enabled) {
            return { allowed: true };
        }

        const authors = this._extractAuthors(versionData);

        if (authors.length === 0) {
            if (this.config.requireVerifiedEmail) {
                return {
                    allowed: false,
                    reason: 'No author information available',
                    blockedBy: 'email',
                };
            }
            return { allowed: true };
        }

        for (const author of authors) {
            const result = this._checkSingleAuthor(author);
            if (!result.allowed) {
                return result;
            }
        }

        return { allowed: true };
    }

    /**
     * Extract author information from package version data
     */
    private _extractAuthors(versionData: Version): AuthorInfo[] {
        const authors: AuthorInfo[] = [];

        if (versionData.author) {
            authors.push(this._normalizeAuthor(versionData.author));
        }

        if (Array.isArray(versionData.maintainers)) {
            versionData.maintainers.forEach(maintainer => {
                authors.push(this._normalizeAuthor(maintainer));
            });
        }

        if (Array.isArray(versionData.contributors)) {
            versionData.contributors.forEach(contributor => {
                authors.push(this._normalizeAuthor(contributor));
            });
        }

        return authors;
    }

    /**
     * Normalize author data to AuthorInfo format
     */
    private _normalizeAuthor(author: any): AuthorInfo {
        if (typeof author === 'string') {
            const emailMatch = author.match(/<([^>]+)>/);
            const nameMatch = author.match(/^([^<]+)/);

            return {
                name: nameMatch ? nameMatch[1].trim() : undefined,
                email: emailMatch ? emailMatch[1].trim() : undefined,
            };
        }

        return {
            name: author.name,
            email: author.email,
            url: author.url,
        };
    }

    /**
     * Check a single author against all blocking rules
     */
    private _checkSingleAuthor(author: AuthorInfo): AuthorCheckResult {
        // Check blocked author names
        if (author.name) {
            const normalizedName = author.name.toLowerCase().trim();

            if (this.blockedAuthors.has(normalizedName)) {
                return {
                    allowed: false,
                    reason: `Author name "${author.name}" is blocked`,
                    blockedBy: 'name',
                    authorInfo: author,
                };
            }

            for (const pattern of this.blockedAuthorPatterns) {
                if (pattern.test(author.name)) {
                    return {
                        allowed: false,
                        reason: `Author name "${author.name}" matches blocked pattern`,
                        blockedBy: 'name',
                        authorInfo: author,
                    };
                }
            }
        }

        // Check blocked emails
        if (author.email) {
            const normalizedEmail = author.email.toLowerCase().trim();

            if (this.blockedEmails.has(normalizedEmail)) {
                return {
                    allowed: false,
                    reason: `Author email "${author.email}" is blocked`,
                    blockedBy: 'email',
                    authorInfo: author,
                };
            }

            for (const pattern of this.blockedEmailPatterns) {
                if (pattern.test(author.email)) {
                    return {
                        allowed: false,
                        reason: `Author email "${author.email}" matches blocked pattern`,
                        blockedBy: 'email',
                        authorInfo: author,
                    };
                }
            }

            // Check blocked email domains
            for (const domain of this.blockedEmailDomains) {
                if (normalizedEmail.endsWith(domain) || normalizedEmail.includes(`@${domain}`)) {
                    return {
                        allowed: false,
                        reason: `Author email domain "${domain}" is blocked`,
                        blockedBy: 'domain',
                        authorInfo: author,
                    };
                }
            }

            // Check blocked regions
            for (const [region, domains] of this.regionDomainMap.entries()) {
                for (const domain of domains) {
                    if (normalizedEmail.endsWith(domain) ||
                        normalizedEmail.endsWith(`@${domain}`) ||
                        normalizedEmail.includes(`@${domain}`)) {
                        return {
                            allowed: false,
                            reason: `Author email from blocked region "${region.toUpperCase()}"`,
                            blockedBy: 'region',
                            authorInfo: author,
                        };
                    }
                }
            }
        }

        return { allowed: true };
    }

    /**
     * Get summary of configuration
     */
    getSummary(): {
        enabled: boolean;
        blockedAuthors: number;
        blockedAuthorPatterns: number;
        blockedEmails: number;
        blockedEmailPatterns: number;
        blockedEmailDomains: number;
        blockedRegions: number;
    } {
        return {
            enabled: this.config?.enabled || false,
            blockedAuthors: this.blockedAuthors.size,
            blockedAuthorPatterns: this.blockedAuthorPatterns.length,
            blockedEmails: this.blockedEmails.size,
            blockedEmailPatterns: this.blockedEmailPatterns.length,
            blockedEmailDomains: this.blockedEmailDomains.size,
            blockedRegions: this.regionDomainMap.size,
        };
    }
}
