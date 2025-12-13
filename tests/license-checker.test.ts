import { LicenseChecker } from '../src/lib/license-checker';
import { Version } from '@verdaccio/types';

describe('LicenseChecker', () => {
    describe('with allowed list', () => {
        let checker: LicenseChecker;

        beforeEach(() => {
            checker = new LicenseChecker({
                allowed: ['MIT', 'Apache-2.0', 'BSD-3-Clause'],
                blocked: [],
                requireLicense: true,
            });
        });

        it('should allow packages with MIT license', () => {
            const versionData = { license: 'MIT' } as Version;
            const result = checker.checkLicense(versionData);

            expect(result.allowed).toBe(true);
            expect(result.license).toBe('MIT');
        });

        it('should allow packages with Apache-2.0 license', () => {
            const versionData = { license: 'Apache-2.0' } as Version;
            const result = checker.checkLicense(versionData);

            expect(result.allowed).toBe(true);
        });

        it('should block packages with GPL-3.0 license', () => {
            const versionData = { license: 'GPL-3.0' } as Version;
            const result = checker.checkLicense(versionData);

            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('not in allowed list');
        });

        it('should block packages without license when required', () => {
            const versionData = {} as Version;
            const result = checker.checkLicense(versionData);

            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('does not specify a license');
        });

        it('should handle SPDX license object format', () => {
            const versionData = { license: { type: 'MIT' } } as any;
            const result = checker.checkLicense(versionData);

            expect(result.allowed).toBe(true);
            expect(result.license).toBe('MIT');
        });
    });

    describe('with blocked list', () => {
        let checker: LicenseChecker;

        beforeEach(() => {
            checker = new LicenseChecker({
                allowed: [],
                blocked: ['GPL-3.0', 'AGPL-3.0'],
                requireLicense: false,
            });
        });

        it('should block packages with GPL-3.0 license', () => {
            const versionData = { license: 'GPL-3.0' } as Version;
            const result = checker.checkLicense(versionData);

            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('is in blocked list');
        });

        it('should allow packages with MIT license', () => {
            const versionData = { license: 'MIT' } as Version;
            const result = checker.checkLicense(versionData);

            expect(result.allowed).toBe(true);
        });

        it('should allow packages without license when not required', () => {
            const versionData = {} as Version;
            const result = checker.checkLicense(versionData);

            expect(result.allowed).toBe(true);
        });
    });

    describe('SPDX expression handling', () => {
        let checker: LicenseChecker;

        beforeEach(() => {
            checker = new LicenseChecker({
                allowed: ['MIT', 'Apache-2.0'],
                blocked: ['GPL-3.0'],
                requireLicense: true,
            });
        });

        it('should handle OR expressions in allowed list', () => {
            const versionData = { license: 'MIT OR Apache-2.0' } as Version;
            const result = checker.checkLicense(versionData);

            expect(result.allowed).toBe(true);
        });

        it('should block OR expressions with blocked license', () => {
            const versionData = { license: 'MIT OR GPL-3.0' } as Version;
            const result = checker.checkLicense(versionData);

            expect(result.allowed).toBe(false);
        });

        it('should handle AND expressions', () => {
            const versionData = { license: 'MIT AND Apache-2.0' } as Version;
            const result = checker.checkLicense(versionData);

            expect(result.allowed).toBe(true);
        });
    });

    describe('static methods', () => {
        it('should return common open source licenses', () => {
            const licenses = LicenseChecker.getCommonOpenSourceLicenses();

            expect(licenses).toContain('MIT');
            expect(licenses).toContain('Apache-2.0');
            expect(licenses).toContain('BSD-3-Clause');
            expect(licenses.length).toBeGreaterThan(0);
        });

        it('should return common copyleft licenses', () => {
            const licenses = LicenseChecker.getCopyleftLicenses();

            expect(licenses).toContain('GPL-3.0');
            expect(licenses).toContain('AGPL-3.0');
            expect(licenses).toContain('LGPL-3.0');
            expect(licenses.length).toBeGreaterThan(0);
        });
    });

    describe('edge cases', () => {
        let checker: LicenseChecker;

        beforeEach(() => {
            checker = new LicenseChecker({
                allowed: ['MIT'],
                blocked: [],
                requireLicense: true,
            });
        });

        it('should handle UNLICENSED as missing license', () => {
            const versionData = { license: 'UNLICENSED' } as Version;
            const result = checker.checkLicense(versionData);

            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('does not specify a license');
        });

        it('should handle empty string license', () => {
            const versionData = { license: '' } as Version;
            const result = checker.checkLicense(versionData);

            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('does not specify a license');
        });
    });
});
