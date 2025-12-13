import { WhitelistChecker } from '../src/lib/whitelist-checker';

describe('WhitelistChecker', () => {
    describe('exact package matching', () => {
        let checker: WhitelistChecker;

        beforeEach(() => {
            checker = new WhitelistChecker({
                packages: ['lodash', 'express', '@types/node'],
                patterns: [],
            });
        });

        it('should allow whitelisted packages', () => {
            const result = checker.isWhitelisted('lodash');
            expect(result.allowed).toBe(true);
        });

        it('should block non-whitelisted packages', () => {
            const result = checker.isWhitelisted('evil-package');
            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('not in whitelist');
        });

        it('should allow scoped packages', () => {
            const result = checker.isWhitelisted('@types/node');
            expect(result.allowed).toBe(true);
        });
    });

    describe('pattern matching', () => {
        let checker: WhitelistChecker;

        beforeEach(() => {
            checker = new WhitelistChecker({
                packages: [],
                patterns: ['^@company/.*', '^lodash-.*'],
            });
        });

        it('should allow packages matching patterns', () => {
            const result1 = checker.isWhitelisted('@company/utils');
            const result2 = checker.isWhitelisted('lodash-es');

            expect(result1.allowed).toBe(true);
            expect(result2.allowed).toBe(true);
        });

        it('should block packages not matching patterns', () => {
            const result = checker.isWhitelisted('random-package');
            expect(result.allowed).toBe(false);
        });
    });

    describe('version constraints', () => {
        let checker: WhitelistChecker;

        beforeEach(() => {
            checker = new WhitelistChecker({
                packages: ['lodash'],
                patterns: [],
                versions: {
                    'lodash': '^4.17.21'
                },
            });
        });

        it('should allow versions matching constraint', () => {
            const result = checker.isWhitelisted('lodash', '4.17.21');
            expect(result.allowed).toBe(true);
        });

        it('should allow versions within range', () => {
            const result = checker.isWhitelisted('lodash', '4.18.0');
            expect(result.allowed).toBe(true);
        });

        it('should block versions outside constraint', () => {
            const result = checker.isWhitelisted('lodash', '3.10.1');
            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('does not satisfy whitelist constraint');
        });

        it('should allow package without version check if no version specified', () => {
            const result = checker.isWhitelisted('lodash');
            expect(result.allowed).toBe(true);
        });
    });

    describe('package management', () => {
        let checker: WhitelistChecker;

        beforeEach(() => {
            checker = new WhitelistChecker({
                packages: ['lodash'],
                patterns: [],
            });
        });

        it('should add package to whitelist', () => {
            checker.addPackage('express');
            const result = checker.isWhitelisted('express');
            expect(result.allowed).toBe(true);
        });

        it('should add package with version constraint', () => {
            checker.addPackage('express', '^4.0.0');
            const result1 = checker.isWhitelisted('express', '4.18.0');
            const result2 = checker.isWhitelisted('express', '3.0.0');

            expect(result1.allowed).toBe(true);
            expect(result2.allowed).toBe(false);
        });

        it('should remove package from whitelist', () => {
            checker.removePackage('lodash');
            const result = checker.isWhitelisted('lodash');
            expect(result.allowed).toBe(false);
        });

        it('should not duplicate packages', () => {
            checker.addPackage('lodash');
            checker.addPackage('lodash');
            const summary = checker.getSummary();
            expect(summary.totalPackages).toBe(1);
        });

        it('should add patterns', () => {
            checker.addPattern('^@test/.*');
            const result = checker.isWhitelisted('@test/package');
            expect(result.allowed).toBe(true);
        });
    });

    describe('getSummary', () => {
        it('should return correct summary', () => {
            const checker = new WhitelistChecker({
                packages: ['lodash', 'express', 'react'],
                patterns: ['^@company/.*', '^@types/.*'],
                autoApprove: {
                    minDownloads: 1000,
                },
            });

            const summary = checker.getSummary();

            expect(summary.totalPackages).toBe(3);
            expect(summary.totalPatterns).toBe(2);
            expect(summary.hasAutoApprove).toBe(true);
        });

        it('should handle empty whitelist', () => {
            const checker = new WhitelistChecker({
                packages: [],
                patterns: [],
            });

            const summary = checker.getSummary();

            expect(summary.totalPackages).toBe(0);
            expect(summary.totalPatterns).toBe(0);
            expect(summary.hasAutoApprove).toBe(false);
        });
    });

    describe('auto-approve criteria', () => {
        let checker: WhitelistChecker;

        beforeEach(() => {
            checker = new WhitelistChecker({
                packages: [],
                patterns: [],
                autoApprove: {
                    minDownloads: 10000,
                    minStars: 100,
                    verifiedPublisher: true,
                },
            });
        });

        it('should return not approved with placeholder message', async () => {
            const result = await checker.meetsAutoApproveCriteria('some-package');

            expect(result.approved).toBe(false);
            expect(result.reason).toContain('not implemented');
        });
    });

    describe('edge cases', () => {
        it('should handle invalid regex patterns gracefully', () => {
            // Mock console.error to avoid test output pollution
            const consoleError = jest.spyOn(console, 'error').mockImplementation();

            const checker = new WhitelistChecker({
                packages: [],
                patterns: ['[invalid(regex'],
            });

            const result = checker.isWhitelisted('any-package');
            expect(result.allowed).toBe(false);
            expect(consoleError).toHaveBeenCalled();

            consoleError.mockRestore();
        });

        it('should handle empty configuration', () => {
            const checker = new WhitelistChecker();
            const result = checker.isWhitelisted('any-package');
            expect(result.allowed).toBe(false);
        });
    });
});
