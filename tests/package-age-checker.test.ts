import { PackageAgeChecker } from '../src/lib/package-age-checker';
import { Package } from '@verdaccio/types';

describe('PackageAgeChecker', () => {
    function createMockPackage(name: string, createdDaysAgo: number, versions: Record<string, number>): Package {
        const now = new Date();
        const createdDate = new Date(now.getTime() - createdDaysAgo * 24 * 60 * 60 * 1000);

        const time: Record<string, string> = {
            created: createdDate.toISOString(),
            modified: now.toISOString(),
        };

        // Add version timestamps
        Object.entries(versions).forEach(([version, daysAgo]) => {
            const versionDate = new Date(now.getTime() - daysAgo * 24 * 60 * 60 * 1000);
            time[version] = versionDate.toISOString();
        });

        return {
            name,
            versions: {},
            'dist-tags': {},
            time,
            _id: name,
            readme: '',
            _rev: '',
            _attachments: {},
            _distfiles: {},
            _uplinks: {},
        } as any;
    }

    describe('package age checking', () => {
        it('should allow packages older than minimum age', () => {
            const checker = new PackageAgeChecker({
                enabled: true,
                minPackageAgeDays: 7,
            });

            const packageData = createMockPackage('test-package', 10, {});
            const result = checker.checkPackageAge(packageData);

            expect(result.allowed).toBe(true);
            expect(result.ageDays).toBeGreaterThanOrEqual(10);
        });

        it('should block packages younger than minimum age', () => {
            const checker = new PackageAgeChecker({
                enabled: true,
                minPackageAgeDays: 7,
            });

            const packageData = createMockPackage('test-package', 3, {});
            const result = checker.checkPackageAge(packageData);

            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('only 3 days old');
            expect(result.ageDays).toBe(3);
        });

        it('should allow packages in warn-only mode', () => {
            const checker = new PackageAgeChecker({
                enabled: true,
                minPackageAgeDays: 7,
                warnOnly: true,
            });

            const packageData = createMockPackage('test-package', 3, {});
            const result = checker.checkPackageAge(packageData);

            expect(result.allowed).toBe(true);
            expect(result.warnOnly).toBe(true);
            expect(result.reason).toContain('only 3 days old');
        });

        it('should allow packages when disabled', () => {
            const checker = new PackageAgeChecker({
                enabled: false,
                minPackageAgeDays: 7,
            });

            const packageData = createMockPackage('test-package', 1, {});
            const result = checker.checkPackageAge(packageData);

            expect(result.allowed).toBe(true);
        });

        it('should handle packages without creation date', () => {
            const checker = new PackageAgeChecker({
                enabled: true,
                minPackageAgeDays: 7,
            });

            const packageData = {
                name: 'test-package',
                versions: {},
                'dist-tags': {},
                time: {},
                _id: 'test-package',
                readme: '',
                _rev: '',
                _attachments: {},
                _distfiles: {},
                _uplinks: {},
            } as any;

            const result = checker.checkPackageAge(packageData);

            expect(result.allowed).toBe(true);
            expect(result.reason).toContain('Cannot determine package creation date');
        });

        it('should fallback to oldest version when no created field', () => {
            const checker = new PackageAgeChecker({
                enabled: true,
                minPackageAgeDays: 7,
            });

            const now = new Date();
            const oldDate = new Date(now.getTime() - 10 * 24 * 60 * 60 * 1000);

            const packageData = {
                name: 'test-package',
                versions: {},
                'dist-tags': {},
                time: {
                    '1.0.0': oldDate.toISOString(),
                    '1.0.1': now.toISOString(),
                },
                _id: 'test-package',
                readme: '',
                _rev: '',
                _attachments: {},
                _distfiles: {},
                _uplinks: {},
            } as any;

            const result = checker.checkPackageAge(packageData);

            expect(result.allowed).toBe(true);
            expect(result.ageDays).toBeGreaterThanOrEqual(9);
        });
    });

    describe('version age checking', () => {
        it('should allow versions older than minimum age', () => {
            const checker = new PackageAgeChecker({
                enabled: true,
                minPackageAgeDays: 0,
                minVersionAgeDays: 3,
            });

            const packageData = createMockPackage('test-package', 10, {
                '1.0.0': 5,
                '1.0.1': 1,
            });

            const result = checker.checkVersionAge(packageData, '1.0.0');

            expect(result.allowed).toBe(true);
            expect(result.ageDays).toBeGreaterThanOrEqual(5);
        });

        it('should block versions younger than minimum age', () => {
            const checker = new PackageAgeChecker({
                enabled: true,
                minPackageAgeDays: 0,
                minVersionAgeDays: 3,
            });

            const packageData = createMockPackage('test-package', 10, {
                '1.0.0': 5,
                '1.0.1': 1,
            });

            const result = checker.checkVersionAge(packageData, '1.0.1');

            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('only 1 days old');
            expect(result.ageDays).toBe(1);
        });

        it('should allow versions in warn-only mode', () => {
            const checker = new PackageAgeChecker({
                enabled: true,
                minPackageAgeDays: 0,
                minVersionAgeDays: 3,
                warnOnly: true,
            });

            const packageData = createMockPackage('test-package', 10, {
                '1.0.1': 1,
            });

            const result = checker.checkVersionAge(packageData, '1.0.1');

            expect(result.allowed).toBe(true);
            expect(result.warnOnly).toBe(true);
        });

        it('should skip version check when not configured', () => {
            const checker = new PackageAgeChecker({
                enabled: true,
                minPackageAgeDays: 7,
                // minVersionAgeDays not set
            });

            const packageData = createMockPackage('test-package', 10, {
                '1.0.1': 1,
            });

            const result = checker.checkVersionAge(packageData, '1.0.1');

            expect(result.allowed).toBe(true);
        });

        it('should handle missing version date', () => {
            const checker = new PackageAgeChecker({
                enabled: true,
                minPackageAgeDays: 0,
                minVersionAgeDays: 3,
            });

            const packageData = createMockPackage('test-package', 10, {
                '1.0.0': 5,
            });

            const result = checker.checkVersionAge(packageData, '1.0.1');

            expect(result.allowed).toBe(true);
            expect(result.reason).toContain('Cannot determine version');
        });
    });

    describe('getSummary', () => {
        it('should return correct configuration summary', () => {
            const checker = new PackageAgeChecker({
                enabled: true,
                minPackageAgeDays: 7,
                minVersionAgeDays: 3,
                warnOnly: false,
            });

            const summary = checker.getSummary();

            expect(summary.enabled).toBe(true);
            expect(summary.minPackageAgeDays).toBe(7);
            expect(summary.minVersionAgeDays).toBe(3);
            expect(summary.warnOnly).toBe(false);
        });

        it('should handle default values', () => {
            const checker = new PackageAgeChecker();

            const summary = checker.getSummary();

            expect(summary.enabled).toBe(false);
            expect(summary.minPackageAgeDays).toBe(0);
            expect(summary.warnOnly).toBe(false);
        });
    });
});
