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
                    error: 'Package blocked by security filter',
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
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalled();

            const jsonCall = res.json.mock.calls[0][0];
            expect(jsonCall.name).toBe('hawk');
            expect(jsonCall.versions).toEqual({});
            expect(jsonCall.security).toBeDefined();
            expect(jsonCall.security.blocked).toBe(true);

            // next() should NOT be called because we sent the response
            expect(next).not.toHaveBeenCalled();
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
});
