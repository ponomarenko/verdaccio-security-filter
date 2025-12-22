import { AuthorChecker } from '../src/lib/author-checker';
import { Version } from '@verdaccio/types';

describe('AuthorChecker', () => {
    function createMockVersion(author?: any, maintainers?: any[], contributors?: any[]): Version {
        return {
            name: 'test-package',
            version: '1.0.0',
            author,
            maintainers,
            contributors,
        } as any;
    }

    describe('disabled state', () => {
        it('should allow all authors when disabled', () => {
            const checker = new AuthorChecker({ enabled: false });
            const versionData = createMockVersion('John Doe <john@example.ru>');
            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(true);
        });

        it('should allow packages without config', () => {
            const checker = new AuthorChecker();
            const versionData = createMockVersion('John Doe <john@example.ru>');
            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(true);
        });
    });

    describe('blocked authors by name', () => {
        it('should block author by exact name match', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedAuthors: ['John Doe', 'Jane Smith'],
            });

            const versionData = createMockVersion('John Doe <john@example.com>');
            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(false);
            expect(result.blockedBy).toBe('name');
            expect(result.reason).toContain('John Doe');
        });

        it('should be case insensitive for author names', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedAuthors: ['john doe'],
            });

            const versionData = createMockVersion('John Doe <john@example.com>');
            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(false);
            expect(result.blockedBy).toBe('name');
        });

        it('should allow non-blocked authors', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedAuthors: ['Jane Smith'],
            });

            const versionData = createMockVersion('John Doe <john@example.com>');
            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(true);
        });
    });

    describe('blocked authors by pattern', () => {
        it('should block author by regex pattern', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedAuthorPatterns: ['^Ivan.*', 'Dmitry$'],
            });

            const versionData = createMockVersion('Ivan Petrov <ivan@example.com>');
            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(false);
            expect(result.blockedBy).toBe('name');
            expect(result.reason).toContain('matches blocked pattern');
        });

        it('should block author matching end pattern', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedAuthorPatterns: ['Dmitry$'],
            });

            const versionData = createMockVersion('Sergey Dmitry <sergey@example.com>');
            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(false);
        });
    });

    describe('blocked emails by exact match', () => {
        it('should block author by exact email match', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedEmails: ['john@example.ru', 'jane@yandex.ru'],
            });

            const versionData = createMockVersion('John Doe <john@example.ru>');
            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(false);
            expect(result.blockedBy).toBe('email');
            expect(result.reason).toContain('john@example.ru');
        });

        it('should be case insensitive for emails', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedEmails: ['john@example.ru'],
            });

            const versionData = createMockVersion('John Doe <JOHN@EXAMPLE.RU>');
            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(false);
        });
    });

    describe('blocked emails by pattern', () => {
        it('should block email by regex pattern', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedEmailPatterns: ['.*@yandex\\.ru$', '.*@mail\\.ru$'],
            });

            const versionData = createMockVersion('John Doe <john@yandex.ru>');
            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(false);
            expect(result.blockedBy).toBe('email');
            expect(result.reason).toContain('matches blocked pattern');
        });
    });

    describe('blocked email domains', () => {
        it('should block email by domain suffix', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedEmailDomains: ['.ru', 'yandex.ru'],
            });

            const versionData = createMockVersion('John Doe <john@example.ru>');
            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(false);
            expect(result.blockedBy).toBe('domain');
            expect(result.reason).toContain('.ru');
        });

        it('should block email by specific domain', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedEmailDomains: ['yandex.ru'],
            });

            const versionData = createMockVersion('John Doe <john@yandex.ru>');
            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(false);
            expect(result.blockedBy).toBe('domain');
        });

        it('should allow non-blocked domains', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedEmailDomains: ['.ru'],
            });

            const versionData = createMockVersion('John Doe <john@example.com>');
            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(true);
        });
    });

    describe('blocked regions', () => {
        it('should block Russian email domains', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedRegions: ['ru'],
            });

            const testCases = [
                'john@example.ru',
                'jane@yandex.ru',
                'bob@mail.ru',
                'alice@rambler.ru',
            ];

            testCases.forEach(email => {
                const versionData = createMockVersion(`Author <${email}>`);
                const result = checker.checkAuthor(versionData);

                expect(result.allowed).toBe(false);
                expect(result.blockedBy).toBe('region');
                expect(result.reason).toContain('RU');
            });
        });

        it('should block Chinese email domains', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedRegions: ['cn'],
            });

            const testCases = [
                'john@example.cn',
                'jane@qq.com',
                'bob@163.com',
            ];

            testCases.forEach(email => {
                const versionData = createMockVersion(`Author <${email}>`);
                const result = checker.checkAuthor(versionData);

                expect(result.allowed).toBe(false);
                expect(result.blockedBy).toBe('region');
                expect(result.reason).toContain('CN');
            });
        });

        it('should block multiple regions', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedRegions: ['ru', 'cn', 'by'],
            });

            const versionData1 = createMockVersion('Author <john@example.ru>');
            const result1 = checker.checkAuthor(versionData1);
            expect(result1.allowed).toBe(false);

            const versionData2 = createMockVersion('Author <jane@qq.com>');
            const result2 = checker.checkAuthor(versionData2);
            expect(result2.allowed).toBe(false);

            const versionData3 = createMockVersion('Author <bob@tut.by>');
            const result3 = checker.checkAuthor(versionData3);
            expect(result3.allowed).toBe(false);
        });

        it('should allow non-blocked regions', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedRegions: ['ru', 'cn'],
            });

            const versionData = createMockVersion('Author <john@example.com>');
            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(true);
        });
    });

    describe('maintainers and contributors', () => {
        it('should check maintainers list', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedEmails: ['blocked@example.ru'],
            });

            const versionData = createMockVersion(
                'John Doe <john@example.com>',
                [
                    { name: 'Maintainer', email: 'blocked@example.ru' },
                    { name: 'Other', email: 'other@example.com' },
                ]
            );

            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(false);
            expect(result.blockedBy).toBe('email');
        });

        it('should check contributors list', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedRegions: ['ru'],
            });

            const versionData = createMockVersion(
                'John Doe <john@example.com>',
                [],
                [
                    { name: 'Contributor', email: 'contrib@yandex.ru' },
                ]
            );

            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(false);
            expect(result.blockedBy).toBe('region');
        });

        it('should allow if all authors are safe', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedRegions: ['ru'],
            });

            const versionData = createMockVersion(
                'John Doe <john@example.com>',
                [{ name: 'Maintainer', email: 'maintainer@example.com' }],
                [{ name: 'Contributor', email: 'contrib@example.com' }]
            );

            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(true);
        });
    });

    describe('author format parsing', () => {
        it('should parse string author format', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedEmails: ['john@example.ru'],
            });

            const versionData = createMockVersion('John Doe <john@example.ru>');
            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(false);
            expect(result.authorInfo?.name).toBe('John Doe');
            expect(result.authorInfo?.email).toBe('john@example.ru');
        });

        it('should parse object author format', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedEmails: ['john@example.ru'],
            });

            const versionData = createMockVersion({
                name: 'John Doe',
                email: 'john@example.ru',
                url: 'https://example.com',
            });

            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(false);
            expect(result.authorInfo?.email).toBe('john@example.ru');
        });

        it('should handle author without email', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedAuthors: ['John Doe'],
            });

            const versionData = createMockVersion('John Doe');
            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(false);
        });
    });

    describe('requireVerifiedEmail', () => {
        it('should block packages without author info when required', () => {
            const checker = new AuthorChecker({
                enabled: true,
                requireVerifiedEmail: true,
            });

            const versionData = createMockVersion();
            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('No author information');
        });

        it('should allow packages with author info when required', () => {
            const checker = new AuthorChecker({
                enabled: true,
                requireVerifiedEmail: true,
            });

            const versionData = createMockVersion('John Doe <john@example.com>');
            const result = checker.checkAuthor(versionData);

            expect(result.allowed).toBe(true);
        });
    });

    describe('getSummary', () => {
        it('should return configuration summary', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedAuthors: ['Author1', 'Author2'],
                blockedAuthorPatterns: ['^Ivan.*'],
                blockedEmails: ['email1@example.com', 'email2@example.com'],
                blockedEmailPatterns: ['.*@yandex\\.ru$'],
                blockedEmailDomains: ['.ru', '.cn'],
                blockedRegions: ['ru', 'cn', 'by'],
            });

            const summary = checker.getSummary();

            expect(summary.enabled).toBe(true);
            expect(summary.blockedAuthors).toBe(2);
            expect(summary.blockedAuthorPatterns).toBe(1);
            expect(summary.blockedEmails).toBe(2);
            expect(summary.blockedEmailPatterns).toBe(1);
            expect(summary.blockedEmailDomains).toBe(2);
            expect(summary.blockedRegions).toBe(3);
        });

        it('should return zero counts when disabled', () => {
            const checker = new AuthorChecker();
            const summary = checker.getSummary();

            expect(summary.enabled).toBe(false);
            expect(summary.blockedAuthors).toBe(0);
            expect(summary.blockedRegions).toBe(0);
        });
    });

    describe('combined rules', () => {
        it('should block when any rule matches', () => {
            const checker = new AuthorChecker({
                enabled: true,
                blockedAuthors: ['John Doe'],
                blockedEmails: ['blocked@example.com'],
                blockedRegions: ['ru'],
            });

            const testCases = [
                { author: 'John Doe <john@safe.com>', shouldBlock: true },
                { author: 'Safe Author <blocked@example.com>', shouldBlock: true },
                { author: 'Safe Author <safe@yandex.ru>', shouldBlock: true },
                { author: 'Safe Author <safe@example.com>', shouldBlock: false },
            ];

            testCases.forEach(({ author, shouldBlock }) => {
                const versionData = createMockVersion(author);
                const result = checker.checkAuthor(versionData);

                expect(result.allowed).toBe(!shouldBlock);
            });
        });
    });
});
