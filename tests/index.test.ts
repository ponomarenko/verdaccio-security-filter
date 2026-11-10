import SecurityFilterPlugin from '../src/index';
import { PluginOptions } from '@verdaccio/types';

describe('SecurityFilterPlugin', () => {
    const pluginOptions = {
        config: {},
        logger: {
            error: jest.fn(),
            info: jest.fn(),
            debug: jest.fn(),
            warn: jest.fn(),
            child: jest.fn(),
            trace: jest.fn(),
            http: jest.fn(),
        },
    } as any;

    describe('constructor', () => {
        it('should initialize with default configuration', () => {
            const config = {
                mode: 'blacklist',
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);

            expect(plugin).toBeDefined();
            expect(plugin.config).toBeDefined();
            expect(plugin.logger).toBeDefined();
        });

        it('should initialize with custom logger config', () => {
            const config = {
                mode: 'whitelist',
                logger: {
                    level: 'debug',
                    enabled: true,
                },
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);

            expect(plugin.config.logger).toBeDefined();
            expect(plugin.config.logger?.level).toBe('debug');
        });

        it('should parse version range rules', () => {
            const config = {
                versionRangeRules: [
                    {
                        package: 'lodash',
                        range: '4.17.0 - 4.17.20',
                        strategy: 'block',
                        reason: 'Vulnerable',
                    },
                ],
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);

            expect(plugin).toBeDefined();
        });

        it('should initialize whitelist checker in whitelist mode', () => {
            const config = {
                mode: 'whitelist',
                whitelist: {
                    packages: ['lodash', 'express'],
                    patterns: [],
                },
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);

            expect(plugin.config.mode).toBe('whitelist');
            expect(plugin.config.whitelist).toBeDefined();
        });
    });

    describe('register_middlewares', () => {
        it('should register middleware function', () => {
            const config = {
                mode: 'whitelist',
                whitelist: {
                    packages: ['lodash'],
                    patterns: [],
                },
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);

            const app = {
                use: jest.fn(),
            } as any;

            plugin.register_middlewares(app, {} as any, {} as any);

            expect(app.use).toHaveBeenCalled();
        });

        it('should create middleware that can process requests', () => {
            const config = {
                mode: 'whitelist',
                whitelist: {
                    packages: ['lodash'],
                    patterns: [],
                },
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);

            let middlewareFunction: any;
            const app = {
                use: jest.fn((fn) => {
                    middlewareFunction = fn;
                }),
            } as any;

            plugin.register_middlewares(app, {} as any, {} as any);

            expect(middlewareFunction).toBeDefined();
            expect(typeof middlewareFunction).toBe('function');
        });
    });

    describe('middleware blocking logic', () => {
        it('should block tarball downloads for non-whitelisted packages', async () => {
            const config = {
                mode: 'whitelist',
                whitelist: {
                    packages: ['lodash'],
                    patterns: [],
                },
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);

            let middlewareFunction: any;
            const app = {
                use: jest.fn((fn) => {
                    middlewareFunction = fn;
                }),
            } as any;

            plugin.register_middlewares(app, {} as any, {} as any);

            const req = {
                method: 'GET',
                url: '/hawk/-/hawk-9.0.2.tgz',
            } as any;

            const res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn().mockReturnThis(),
                send: jest.fn(),
            } as any;

            const next = jest.fn();

            await middlewareFunction(req, res, next);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    error: 'Package blocked by security filter: Package is not in whitelist',
                    package: 'hawk',
                })
            );
            expect(next).not.toHaveBeenCalled();
        });

        it('should allow tarball downloads for whitelisted packages', async () => {
            const config = {
                mode: 'whitelist',
                whitelist: {
                    packages: ['lodash'],
                    patterns: [],
                },
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);

            let middlewareFunction: any;
            const app = {
                use: jest.fn((fn) => {
                    middlewareFunction = fn;
                }),
            } as any;

            plugin.register_middlewares(app, {} as any, {} as any);

            const req = {
                method: 'GET',
                url: '/lodash/-/lodash-4.17.21.tgz',
            } as any;

            const res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn().mockReturnThis(),
                send: jest.fn(),
            } as any;

            const next = jest.fn();

            await middlewareFunction(req, res, next);

            expect(res.status).not.toHaveBeenCalled();
            expect(next).toHaveBeenCalled();
        });

        it('should intercept metadata responses for blocked packages', async () => {
            const config = {
                mode: 'whitelist',
                whitelist: {
                    packages: ['lodash'],
                    patterns: [],
                },
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);

            let middlewareFunction: any;
            const app = {
                use: jest.fn((fn) => {
                    middlewareFunction = fn;
                }),
            } as any;

            plugin.register_middlewares(app, {} as any, {} as any);

            const req = {
                method: 'GET',
                url: '/hawk',
            } as any;

            const res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn(function (this: any, body: any) {
                    this._lastJsonBody = body;
                    return this;
                }),
                send: jest.fn(),
            } as any;

            const next = jest.fn();

            await middlewareFunction(req, res, next);

            // New behavior: middleware directly responds with blocked package info
            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalled();

            const jsonCall = res.json.mock.calls[0][0];
            expect(jsonCall.package).toBe('hawk');
            expect(jsonCall.error).toBe('Package blocked by security filter: Package is not in whitelist');
            expect(jsonCall.security).toBeDefined();
            expect(jsonCall.security.blocked).toBe(true);

            // next() should NOT be called because we sent the response
            expect(next).not.toHaveBeenCalled();
        });

        it('should decode URL-encoded scoped package names in metadata requests', async () => {
            const plugin = new SecurityFilterPlugin(
                { mode: 'whitelist', whitelist: { packages: ['lodash'], patterns: [] } } as any,
                pluginOptions
            );

            let middlewareFunction: any;
            const app = { use: jest.fn((fn) => { middlewareFunction = fn; }) } as any;
            plugin.register_middlewares(app, {} as any, {} as any);

            const res = { status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis(), send: jest.fn() } as any;
            await middlewareFunction({ method: 'GET', url: '/@vueuse%2fmetadata?write=true' } as any, res, jest.fn());

            expect(res.json.mock.calls[0][0].package).toBe('@vueuse/metadata');
        });

        it.each([
            ['POST', '/-/verdaccio/sec/login'],
            ['PUT', '/@scope%2fname'],
            ['GET', '/-/v1/search'],
        ])('should pass through %s %s untouched', async (method, url) => {
            const plugin = new SecurityFilterPlugin(
                { mode: 'whitelist', whitelist: { packages: [], patterns: [] } } as any,
                pluginOptions
            );
            let middlewareFunction: any;
            const app = { use: jest.fn((fn) => { middlewareFunction = fn; }) } as any;
            plugin.register_middlewares(app, {} as any, {} as any);

            const res = { status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis(), send: jest.fn() } as any;
            const next = jest.fn();
            await middlewareFunction({ method, url } as any, res, next);

            expect(next).toHaveBeenCalledWith();
            expect(res.json).not.toHaveBeenCalled();
        });

        it('should block packages by pattern', async () => {
            const config = {
                mode: 'blacklist',
                blockedPatterns: ['^evil-.*'],
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);

            let middlewareFunction: any;
            const app = {
                use: jest.fn((fn) => {
                    middlewareFunction = fn;
                }),
            } as any;

            plugin.register_middlewares(app, {} as any, {} as any);

            const req = {
                method: 'GET',
                url: '/evil-package/-/evil-package-1.0.0.tgz',
            } as any;

            const res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn().mockReturnThis(),
                send: jest.fn(),
            } as any;

            const next = jest.fn();

            await middlewareFunction(req, res, next);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    reason: 'Package name matches blocked pattern',
                })
            );
        });

        it('should block packages by scope', async () => {
            const config = {
                mode: 'blacklist',
                blockedScopes: ['@malicious'],
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);

            let middlewareFunction: any;
            const app = {
                use: jest.fn((fn) => {
                    middlewareFunction = fn;
                }),
            } as any;

            plugin.register_middlewares(app, {} as any, {} as any);

            const req = {
                method: 'GET',
                url: '/@malicious/package/-/package-1.0.0.tgz',
            } as any;

            const res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn().mockReturnThis(),
                send: jest.fn(),
            } as any;

            const next = jest.fn();

            await middlewareFunction(req, res, next);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    reason: 'Package scope not allowed',
                })
            );
        });

        it('should block specific versions', async () => {
            const config = {
                mode: 'blacklist',
                blockedVersions: ['lodash@4.17.20'],
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);

            let middlewareFunction: any;
            const app = {
                use: jest.fn((fn) => {
                    middlewareFunction = fn;
                }),
            } as any;

            plugin.register_middlewares(app, {} as any, {} as any);

            const req = {
                method: 'GET',
                url: '/lodash/-/lodash-4.17.20.tgz',
            } as any;

            const res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn().mockReturnThis(),
                send: jest.fn(),
            } as any;

            const next = jest.fn();

            await middlewareFunction(req, res, next);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    reason: 'Exact version match in blocklist',
                })
            );
        });
    });

    describe('filter_metadata - packageAge.minVersionAgeDays', () => {
        function makePkg(name: string, versions: Record<string, number>): any {
            const now = new Date();
            const time: Record<string, string> = {
                created: new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000).toISOString(),
                modified: now.toISOString(),
            };
            const versionEntries: Record<string, any> = {};
            for (const [ver, daysAgo] of Object.entries(versions)) {
                time[ver] = new Date(now.getTime() - daysAgo * 24 * 60 * 60 * 1000).toISOString();
                versionEntries[ver] = { name, version: ver };
            }
            return {
                name,
                versions: versionEntries,
                'dist-tags': { latest: Object.keys(versions)[Object.keys(versions).length - 1] },
                time,
                _id: name,
                readme: '',
                _rev: '',
                _attachments: {},
                _distfiles: {},
                _uplinks: {},
            };
        }

        it('should filter out versions newer than minVersionAgeDays', async () => {
            const config = {
                mode: 'blacklist',
                packageAge: {
                    enabled: true,
                    minPackageAgeDays: 0,
                    minVersionAgeDays: 30,
                },
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);
            // 1.0.0 is 60 days old (passes), 2.0.0 is 5 days old (fails)
            const pkg = makePkg('my-lib', { '1.0.0': 60, '2.0.0': 5 });

            const result = await plugin.filter_metadata(pkg);

            expect(result.versions['1.0.0']).toBeDefined();
            expect(result.versions['2.0.0']).toBeUndefined();
        });

        it('should remove dist-tags that point to a filtered version', async () => {
            const config = {
                mode: 'blacklist',
                packageAge: {
                    enabled: true,
                    minPackageAgeDays: 0,
                    minVersionAgeDays: 30,
                },
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);
            const pkg = makePkg('my-lib', { '1.0.0': 60, '2.0.0': 5 });
            // latest points to 2.0.0 which will be filtered
            pkg['dist-tags'] = { latest: '2.0.0', stable: '1.0.0' };

            const result = await plugin.filter_metadata(pkg);

            expect(result['dist-tags']['latest']).toBeUndefined();
            expect(result['dist-tags']['stable']).toBe('1.0.0');
        });

        it('should allow all versions when all pass minVersionAgeDays', async () => {
            const config = {
                mode: 'blacklist',
                packageAge: {
                    enabled: true,
                    minPackageAgeDays: 0,
                    minVersionAgeDays: 3,
                },
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);
            const pkg = makePkg('my-lib', { '1.0.0': 10, '1.0.1': 5 });

            const result = await plugin.filter_metadata(pkg);

            expect(result.versions['1.0.0']).toBeDefined();
            expect(result.versions['1.0.1']).toBeDefined();
        });

        it('should only warn in warnOnly mode without removing versions', async () => {
            const config = {
                mode: 'blacklist',
                packageAge: {
                    enabled: true,
                    minPackageAgeDays: 0,
                    minVersionAgeDays: 30,
                    warnOnly: true,
                },
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);
            const pkg = makePkg('my-lib', { '1.0.0': 60, '2.0.0': 1 });

            const result = await plugin.filter_metadata(pkg);

            // warnOnly: both versions should survive
            expect(result.versions['1.0.0']).toBeDefined();
            expect(result.versions['2.0.0']).toBeDefined();
        });

        it('should not filter versions when minVersionAgeDays is not set', async () => {
            const config = {
                mode: 'blacklist',
                packageAge: {
                    enabled: true,
                    minPackageAgeDays: 0,
                    // no minVersionAgeDays
                },
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);
            const pkg = makePkg('my-lib', { '1.0.0': 60, '2.0.0': 1 });

            const result = await plugin.filter_metadata(pkg);

            expect(result.versions['1.0.0']).toBeDefined();
            expect(result.versions['2.0.0']).toBeDefined();
        });
    });

    describe('filter_metadata - cveCheck.autoBlock', () => {
        function makePkg(name: string, versionNames: string[]): any {
            const versionEntries: Record<string, any> = {};
            for (const ver of versionNames) {
                versionEntries[ver] = { name, version: ver };
            }
            return {
                name,
                versions: versionEntries,
                'dist-tags': { latest: versionNames[versionNames.length - 1] },
                time: {},
                _id: name,
                readme: '',
                _rev: '',
                _attachments: {},
                _distfiles: {},
                _uplinks: {},
            };
        }

        function stubCveChecker(plugin: any, vulnerableVersions: string[]): void {
            plugin.cveChecker.checkVersions = jest.fn(async (packageName: string, versions: string[]) => versions.map(version => ({
                package: packageName,
                version,
                vulnerabilities: vulnerableVersions.includes(version)
                    ? [{ id: 'GHSA-test', severity: 'high', summary: 'test', affectedVersions: [], publishedDate: '', source: 'osv' }]
                    : [],
                isVulnerable: vulnerableVersions.includes(version),
                checkedAt: new Date().toISOString(),
            })));
        }

        it('should only remove the vulnerable version, keeping unaffected versions installable', async () => {
            const config = {
                mode: 'blacklist',
                cveCheck: {
                    enabled: true,
                    autoBlock: true,
                    severity: ['high', 'critical'],
                },
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);
            stubCveChecker(plugin, ['1.0.0']);

            const pkg = makePkg('my-lib', ['1.0.0', '2.0.0']);

            const result = await plugin.filter_metadata(pkg);

            expect(result.versions['1.0.0']).toBeUndefined();
            expect(result.versions['2.0.0']).toBeDefined();
        });

        it('should remove dist-tags pointing to a vulnerable version', async () => {
            const config = {
                mode: 'blacklist',
                cveCheck: {
                    enabled: true,
                    autoBlock: true,
                    severity: ['high', 'critical'],
                },
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);
            stubCveChecker(plugin, ['2.0.0']);

            const pkg = makePkg('my-lib', ['1.0.0', '2.0.0']);
            pkg['dist-tags'] = { latest: '2.0.0', stable: '1.0.0' };

            const result = await plugin.filter_metadata(pkg);

            expect(result['dist-tags']['latest']).toBeUndefined();
            expect(result['dist-tags']['stable']).toBe('1.0.0');
        });

        it('should block the whole package when every version is vulnerable', async () => {
            const config = {
                mode: 'blacklist',
                cveCheck: {
                    enabled: true,
                    autoBlock: true,
                    severity: ['high', 'critical'],
                },
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);
            stubCveChecker(plugin, ['1.0.0', '2.0.0']);
            const recordBlock = jest.spyOn((plugin as any).metrics, 'recordBlock');

            const pkg = makePkg('my-lib', ['1.0.0', '2.0.0']);

            const result: any = await plugin.filter_metadata(pkg);

            expect(result.versions).toEqual({});
            expect(result['dist-tags']).toEqual({});
            expect(result.security).toEqual(expect.objectContaining({
                blocked: true,
                vulnerableVersions: expect.arrayContaining(['1.0.0', '2.0.0']),
            }));
            expect(recordBlock).toHaveBeenCalledWith('my-lib', '*', expect.any(String));
        });

        it.each([
            ['fail-open', false],
            ['fail-closed', true],
        ])('should apply onCveCheckError=%s when the lookup fails', async (onCveCheckError, blocked) => {
            const config = {
                mode: 'blacklist',
                cveCheck: { enabled: true, autoBlock: true, severity: ['high', 'critical'] },
                errorHandling: { onCveCheckError },
            } as any;

            const plugin = new SecurityFilterPlugin(config, pluginOptions);
            (plugin as any).cveChecker.checkVersions = jest.fn().mockRejectedValue(new Error('OSV down'));

            const result: any = await plugin.filter_metadata(makePkg('my-lib', ['1.0.0', '2.0.0']));

            expect(Object.keys(result.versions)).toEqual(blocked ? [] : ['1.0.0', '2.0.0']);
            expect(!!result.security?.blocked).toBe(blocked);
        });
    });

    describe('version rules and patterns', () => {
        async function get(config: any, url: string) {
            const plugin = new SecurityFilterPlugin({ mode: 'blacklist', ...config } as any, pluginOptions);
            let middleware: any;
            plugin.register_middlewares({ use: (fn: any) => { middleware = fn; } } as any, {} as any, {} as any);
            const res = { status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis(), send: jest.fn() } as any;
            const next = jest.fn();
            await middleware({ method: 'GET', url } as any, res, next);
            return { res, next };
        }

        it.each([
            ['foo-2@1.0.0', '/foo-2/-/foo-2-1.0.0.tgz'],
            ['pkg@1.0.0-beta-1', '/pkg/-/pkg-1.0.0-beta-1.tgz'],
            ['@scope/pkg@1.0.0+build.5', '/@scope/pkg/-/pkg-1.0.0+build.5.tgz'],
        ])('should read the tarball version exactly and block %s', async (blocked, url) => {
            const { res, next } = await get({ blockedVersions: [blocked] }, url);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(next).not.toHaveBeenCalled();
        });

        it('should not block a different version of a package whose name ends in a number', async () => {
            const { res, next } = await get({ blockedVersions: ['foo-2@1.0.0'] }, '/foo-2/-/foo-2-1.0.1.tgz');

            expect(res.status).not.toHaveBeenCalled();
            expect(next).toHaveBeenCalledWith();
        });

        it('should skip an invalid blocked pattern instead of failing every request', async () => {
            const { res, next } = await get({ blockedPatterns: ['([', '^evil-'] }, '/lodash');
            expect(res.status).not.toHaveBeenCalled();
            expect(next).toHaveBeenCalledWith();

            const blocked = await get({ blockedPatterns: ['([', '^evil-'] }, '/evil-pkg/-/evil-pkg-1.0.0.tgz');
            expect(blocked.res.status).toHaveBeenCalledWith(403);
        });

        it('should hide versions outside whitelist.versions from metadata', async () => {
            const plugin = new SecurityFilterPlugin({
                mode: 'whitelist',
                whitelist: { packages: ['my-lib', 'free-lib'], patterns: [], versions: { 'my-lib': '^2.0.0' } },
            } as any, pluginOptions);
            const metadata = (name: string) => ({
                name,
                versions: Object.fromEntries(['1.0.0', '2.0.0', '2.1.0', '3.0.0'].map(v => [v, { name, version: v }])),
                'dist-tags': { latest: '3.0.0', stable: '2.1.0' },
            } as any);

            const constrained: any = await plugin.filter_metadata(metadata('my-lib'));
            const unconstrained: any = await plugin.filter_metadata(metadata('free-lib'));

            expect(Object.keys(constrained.versions)).toEqual(['2.0.0', '2.1.0']);
            expect(constrained['dist-tags']).toEqual({ stable: '2.1.0' });
            expect(Object.keys(unconstrained.versions)).toHaveLength(4);
        });

        it.each(['block', 'fallback'])('should hide versions matched by a %s rule or blockedVersions from metadata', async (strategy) => {
            const plugin = new SecurityFilterPlugin({
                mode: 'blacklist',
                blockedVersions: ['my-lib@3.0.0'],
                versionRangeRules: [{ package: 'my-lib', range: '<2.0.0', strategy }],
            } as any, pluginOptions);
            const versions = Object.fromEntries(['1.0.0', '1.5.0', '2.0.0', '3.0.0'].map(v => [v, { name: 'my-lib', version: v }]));

            const result: any = await plugin.filter_metadata({
                name: 'my-lib', versions, 'dist-tags': { latest: '3.0.0', stable: '2.0.0' },
            } as any);

            expect(Object.keys(result.versions)).toEqual(['2.0.0']);
            expect(result['dist-tags']).toEqual({ stable: '2.0.0' });
        });

        it('should report the real plugin version for a blocked package', async () => {
            const plugin = new SecurityFilterPlugin({ mode: 'blacklist', blockedPatterns: ['^evil-'] } as any, pluginOptions);

            const result: any = await plugin.filter_metadata({ name: 'evil-pkg', versions: {}, 'dist-tags': {} } as any);

            expect(result.security.plugin.version).toBe(require('../package.json').version);
        });
    });

    describe('filter_metadata - license and author checks on every version', () => {
        const metadata = (versions: Record<string, any>, latest: string): any => ({
            name: 'my-lib',
            versions: Object.fromEntries(Object.entries(versions).map(([v, extra]) => [v, { name: 'my-lib', version: v, ...extra }])),
            'dist-tags': { latest },
        });
        const licenses = { allowed: ['MIT'], blocked: [], requireLicense: true };
        const authorFilter = { enabled: true, blockedEmailDomains: ['evil.example'] };
        const evil = { author: { name: 'Mallory', email: 'mallory@evil.example' } };
        const good = { author: { name: 'Alice', email: 'alice@good.example' } };

        it('should remove only the versions with a disallowed license', async () => {
            const plugin = new SecurityFilterPlugin({ mode: 'blacklist', licenses } as any, pluginOptions);

            const result: any = await plugin.filter_metadata(metadata({
                '1.0.0': { license: 'GPL-3.0' }, '2.0.0': { license: 'MIT' }, '3.0.0': {},
            }, '2.0.0'));

            expect(Object.keys(result.versions)).toEqual(['2.0.0']);
            expect(result.security).toBeUndefined();
        });

        it('should keep older versions when only the latest has a disallowed license', async () => {
            const plugin = new SecurityFilterPlugin({ mode: 'blacklist', licenses } as any, pluginOptions);

            const result: any = await plugin.filter_metadata(metadata({
                '1.0.0': { license: 'MIT' }, '2.0.0': { license: 'GPL-3.0' },
            }, '2.0.0'));

            expect(Object.keys(result.versions)).toEqual(['1.0.0']);
            expect(result['dist-tags']).toEqual({});
        });

        it('should block the whole package when no version has an allowed license', async () => {
            const plugin = new SecurityFilterPlugin({ mode: 'blacklist', licenses } as any, pluginOptions);

            const result: any = await plugin.filter_metadata(metadata({
                '1.0.0': { license: 'GPL-3.0' }, '2.0.0': { license: 'AGPL-3.0' },
            }, '2.0.0'));

            expect(result.versions).toEqual({});
            expect(result.security).toEqual(expect.objectContaining({ blocked: true, license: 'AGPL-3.0' }));
        });

        it('should still check licenses when the latest dist-tag is missing', async () => {
            const plugin = new SecurityFilterPlugin({ mode: 'blacklist', licenses } as any, pluginOptions);
            const pkg = metadata({ '1.0.0': { license: 'GPL-3.0' }, '2.0.0': { license: 'MIT' } }, '2.0.0');
            pkg['dist-tags'] = {};

            const result: any = await plugin.filter_metadata(pkg);

            expect(Object.keys(result.versions)).toEqual(['2.0.0']);
        });

        it('should apply a blocked-only license list without requiring a license', async () => {
            const plugin = new SecurityFilterPlugin({ mode: 'blacklist', licenses: { blocked: ['GPL-3.0'] } } as any, pluginOptions);

            const result: any = await plugin.filter_metadata(metadata({
                '1.0.0': { license: 'GPL-3.0' }, '2.0.0': { license: 'MIT' }, '3.0.0': {},
            }, '3.0.0'));

            expect(Object.keys(result.versions)).toEqual(['2.0.0', '3.0.0']);
        });

        it('should apply requireLicense on its own', async () => {
            const plugin = new SecurityFilterPlugin({ mode: 'blacklist', licenses: { requireLicense: true } } as any, pluginOptions);

            const result: any = await plugin.filter_metadata(metadata({
                '1.0.0': { license: 'GPL-3.0' }, '2.0.0': {},
            }, '2.0.0'));

            expect(Object.keys(result.versions)).toEqual(['1.0.0']);
        });

        it('should still require a license by default when an allow-list is set', async () => {
            const plugin = new SecurityFilterPlugin({ mode: 'blacklist', licenses: { allowed: ['MIT'] } } as any, pluginOptions);

            const result: any = await plugin.filter_metadata(metadata({ '1.0.0': { license: 'MIT' }, '2.0.0': {} }, '2.0.0'));

            expect(Object.keys(result.versions)).toEqual(['1.0.0']);
        });

        it('should not run the license check for an empty licenses block', async () => {
            const plugin = new SecurityFilterPlugin({ mode: 'blacklist', licenses: {} } as any, pluginOptions);
            const pkg = metadata({ '1.0.0': {}, '2.0.0': { license: 'GPL-3.0' } }, '2.0.0');

            expect(await plugin.filter_metadata(pkg)).toBe(pkg);
        });

        it('should remove only the versions published by a blocked author', async () => {
            const plugin = new SecurityFilterPlugin({ mode: 'blacklist', authorFilter } as any, pluginOptions);

            const result: any = await plugin.filter_metadata(metadata({ '1.0.0': good, '2.0.0': evil, '3.0.0': good }, '3.0.0'));

            expect(Object.keys(result.versions)).toEqual(['1.0.0', '3.0.0']);
        });

        it('should block the whole package when every version has a blocked author', async () => {
            const plugin = new SecurityFilterPlugin({ mode: 'blacklist', authorFilter } as any, pluginOptions);
            const record = jest.spyOn((plugin as any).metrics, 'record');

            const result: any = await plugin.filter_metadata(metadata({ '1.0.0': evil, '2.0.0': evil }, '2.0.0'));

            expect(result.versions).toEqual({});
            expect(result.security).toEqual(expect.objectContaining({ blocked: true, blockedBy: 'domain' }));
            expect(record).toHaveBeenCalledTimes(1);
            expect(record).toHaveBeenCalledWith(expect.objectContaining({ event: 'author_blocked', version: '*' }));
        });

        it('should only warn about blocked authors in warnOnly mode', async () => {
            const plugin = new SecurityFilterPlugin({ mode: 'blacklist', authorFilter: { ...authorFilter, warnOnly: true } } as any, pluginOptions);

            const result: any = await plugin.filter_metadata(metadata({ '1.0.0': good, '2.0.0': evil }, '2.0.0'));

            expect(Object.keys(result.versions)).toEqual(['1.0.0', '2.0.0']);
        });
    });

    describe('dry-run mode', () => {
        const rules = {
            mode: 'blacklist',
            dryRun: true,
            blockedPatterns: ['^evil-'],
            blockedVersions: ['my-lib@1.0.0'],
            metrics: { enabled: true, output: 'stdout' },
        } as any;
        const metadata = (name: string): any => ({
            name,
            versions: { '1.0.0': { name, version: '1.0.0' }, '2.0.0': { name, version: '2.0.0' } },
            'dist-tags': { latest: '2.0.0' },
        });

        beforeEach(() => {
            pluginOptions.logger.warn.mockClear();
        });

        const warnings = () => pluginOptions.logger.warn.mock.calls.map((call: any[]) => call[0]).join('\n');

        it('should return metadata untouched and log what would be removed', async () => {
            const plugin = new SecurityFilterPlugin(rules, pluginOptions);
            const pkg = metadata('my-lib');

            const result = await plugin.filter_metadata(pkg);
            plugin.destroy();

            expect(result).toBe(pkg);
            expect(warnings()).toContain('[DRY RUN]');
            expect(warnings()).toContain('my-lib: would remove 1 of 2 version(s)');
        });

        it('should not block a package that the rules reject entirely', async () => {
            const plugin = new SecurityFilterPlugin(rules, pluginOptions);
            const pkg = metadata('evil-pkg');

            const result: any = await plugin.filter_metadata(pkg);
            plugin.destroy();

            expect(result).toBe(pkg);
            expect(result.security).toBeUndefined();
            expect(warnings()).toContain('evil-pkg: would remove 2 of 2 version(s)');
        });

        it('should let blocked tarball and metadata requests through the middleware and mark the metric', async () => {
            const plugin = new SecurityFilterPlugin(rules, pluginOptions);
            const record = jest.spyOn((plugin as any).metrics.metricsBuffer, 'push');
            let middleware: any;
            plugin.register_middlewares({ use: (fn: any) => { middleware = fn; } } as any, {} as any, {} as any);

            for (const url of ['/my-lib/-/my-lib-1.0.0.tgz', '/evil-pkg']) {
                const res = { status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis(), send: jest.fn() } as any;
                const next = jest.fn();
                await middleware({ method: 'GET', url } as any, res, next);

                expect(res.status).not.toHaveBeenCalled();
                expect(next).toHaveBeenCalledWith();
            }
            plugin.destroy();

            expect(record).toHaveBeenCalledWith(expect.objectContaining({ event: 'block', packageName: 'my-lib', version: '1.0.0', dryRun: true }));
        });

        it('should announce dry-run at start-up and stay silent about it otherwise', () => {
            new SecurityFilterPlugin(rules, pluginOptions).destroy();
            expect(warnings()).toContain('Dry-run mode is on');

            pluginOptions.logger.warn.mockClear();
            new SecurityFilterPlugin({ ...rules, dryRun: false }, pluginOptions).destroy();
            expect(warnings()).not.toContain('DRY RUN');
        });
    });

    describe('block reason for packages blocked in filter_metadata', () => {
        const licenses = { allowed: ['MIT'], blocked: [], requireLicense: true };
        const gplOnly = (name: string): any => ({
            name,
            versions: { '1.0.0': { name, version: '1.0.0', license: 'GPL-3.0' } },
            'dist-tags': { latest: '1.0.0' },
        });

        /** Run a metadata request; `handler` plays Verdaccio: it calls the filter, then sends the packument. */
        async function metadataRequest(config: any, name: string, handler: (filter: SecurityFilterPlugin) => Promise<any>) {
            const middlewarePlugin = new SecurityFilterPlugin(config, pluginOptions);
            const filterPlugin = new SecurityFilterPlugin(config, pluginOptions); // Verdaccio uses separate instances
            let middleware: any;
            middlewarePlugin.register_middlewares({ use: (fn: any) => { middleware = fn; } } as any, {} as any, {} as any);

            const sent: any[] = [];
            const res: any = {
                statusCode: 200,
                status: jest.fn(function (this: any, code: number) { this.statusCode = code; return this; }),
                json: jest.fn(),
                removeHeader: jest.fn(),
                send: jest.fn((body: any) => { sent.push(body); }),
            };
            let finished: Promise<void> = Promise.resolve();
            await middleware({ method: 'GET', url: `/${name}` } as any, res, () => {
                finished = handler(filterPlugin).then(packument => { res.send(JSON.stringify(packument)); });
            });
            await finished;
            return { res, body: JSON.parse(sent[0]) };
        }

        it('should turn the response into a 403 that carries the reason', async () => {
            const { res, body } = await metadataRequest({ mode: 'blacklist', licenses }, 'gpl-lib',
                filter => filter.filter_metadata(gplOnly('gpl-lib')));

            expect(res.statusCode).toBe(403);
            expect(res.removeHeader).toHaveBeenCalledWith('ETag');
            expect(body.error).toBe("Package blocked by security filter: License 'GPL-3.0' is not in allowed list");
            expect(body.security).toEqual(expect.objectContaining({ blocked: true, license: 'GPL-3.0' }));
        });

        it('should leave the response alone when the filter did not block during this request', async () => {
            // an older block of the same package must not leak into a later, allowed response
            await new SecurityFilterPlugin({ mode: 'blacklist', licenses } as any, pluginOptions).filter_metadata(gplOnly('flip-lib'));
            await new Promise(resolve => setTimeout(resolve, 5));

            const { res, body } = await metadataRequest({ mode: 'blacklist', licenses }, 'flip-lib',
                async () => ({ name: 'flip-lib', versions: { '2.0.0': {} } }));

            expect(res.statusCode).toBe(200);
            expect(Object.keys(body.versions)).toEqual(['2.0.0']);
        });

        it('should not answer 403 in dry-run mode', async () => {
            const { res, body } = await metadataRequest({ mode: 'blacklist', licenses, dryRun: true }, 'dry-lib',
                filter => filter.filter_metadata(gplOnly('dry-lib')));

            expect(res.statusCode).toBe(200);
            expect(Object.keys(body.versions)).toEqual(['1.0.0']);
        });
    });

    describe('checker logging', () => {
        it('should send checker messages to the plugin logger, not the console', async () => {
            const consoleError = jest.spyOn(console, 'error').mockImplementation(() => undefined);
            pluginOptions.logger.error.mockClear();

            const plugin = new SecurityFilterPlugin({
                mode: 'whitelist',
                whitelist: { packages: [], patterns: ['(['] },
            } as any, pluginOptions);
            await plugin.filter_metadata({ name: 'any-pkg', versions: {}, 'dist-tags': {} } as any);

            expect(consoleError).not.toHaveBeenCalled();
            expect(pluginOptions.logger.error).toHaveBeenCalledWith(expect.stringContaining('[Security Filter] [Whitelist] Invalid pattern: (['));
            consoleError.mockRestore();
        });
    });

    describe('metrics for filtered versions', () => {
        it('should record one event per filter for a metadata request, not one per version', async () => {
            const plugin = new SecurityFilterPlugin({
                mode: 'blacklist',
                metrics: { enabled: true, output: 'stdout' },
                versionRangeRules: [{ package: 'my-lib', range: '<2.0.0', strategy: 'block' }],
                licenses: { allowed: ['MIT'], blocked: [], requireLicense: true },
            } as any, pluginOptions);
            const events = jest.spyOn((plugin as any).metrics.metricsBuffer, 'push');
            const versions = Object.fromEntries(['1.0.0', '1.1.0', '2.0.0', '2.1.0', '3.0.0'].map(v =>
                [v, { name: 'my-lib', version: v, license: v.startsWith('2.') ? 'GPL-3.0' : 'MIT' }]));
            const pkg = (): any => ({ name: 'my-lib', versions: { ...versions }, 'dist-tags': { latest: '3.0.0' } });

            const result: any = await plugin.filter_metadata(pkg());
            await plugin.filter_metadata(pkg()); // the next request repeats nothing
            plugin.destroy();

            expect(Object.keys(result.versions)).toEqual(['3.0.0']);
            expect(events.mock.calls.map(call => call[0])).toEqual([
                expect.objectContaining({ event: 'block', reason: 'Version blocked by rules', metadata: { versions: ['1.0.0', '1.1.0'] } }),
                expect.objectContaining({ event: 'block', reason: 'License not allowed', metadata: { versions: ['2.0.0', '2.1.0'] } }),
            ]);
        });
    });
});
