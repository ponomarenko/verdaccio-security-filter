/**
 * End-to-end tests: a real Verdaccio, started in-process, loads the BUILT plugin
 * (run `npm run build` first; `npm run test:e2e` does it) and proxies a mock uplink.
 * OSV is stubbed through global fetch, so no test touches the network.
 */
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { runServer } = require('verdaccio');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const VERSIONS = ['1.0.0', '1.5.0', '2.0.0'];
const OSV_URL = 'https://api.osv.dev/';

const realFetch = global.fetch;
/** What the stubbed OSV answers; replaced per test. */
let osvHandler: () => Promise<Response> = async () => Response.json({ vulns: [] });
let osvCalls = 0;

function listen(server: http.Server): Promise<number> {
    return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)));
}

function close(server: http.Server): Promise<void> {
    return new Promise(resolve => server.close(() => resolve()));
}

/** A registry that knows every package name and serves the same three versions for each. */
function createUplink(): http.Server {
    const server = http.createServer((req, res) => {
        const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
        const url = decodeURIComponent(req.url || '');

        if (url.endsWith('.tgz')) {
            res.setHeader('content-type', 'application/octet-stream');
            res.end('fake tarball');
            return;
        }

        const name = url.slice(1);
        const file = name.split('/').pop();
        const versions = Object.fromEntries(VERSIONS.map(version => [version, {
            name,
            version,
            license: version === '1.0.0' ? 'GPL-3.0' : 'MIT',
            dist: { tarball: `${base}/${name}/-/${file}-${version}.tgz`, shasum: 'da39a3ee5e6b4b0d3255bfef95601890afd80709' },
        }]));
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ name, 'dist-tags': { latest: '2.0.0' }, versions, time: {} }));
    });
    return server;
}

interface Registry {
    get(urlPath: string): Promise<{ status: number; body: any }>;
    request(method: string, urlPath: string, body?: unknown): Promise<{ status: number; body: any }>;
    stop(): Promise<void>;
}

async function startRegistry(pluginConfig: Record<string, unknown>): Promise<Registry> {
    const uplink = createUplink();
    const uplinkPort = await listen(uplink);

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vsf-e2e-'));
    fs.mkdirSync(path.join(dir, 'plugins'));
    // Verdaccio resolves "<plugins>/verdaccio-<name>"; point it at this checkout (package.json "main" is the build).
    fs.symlinkSync(REPO_ROOT, path.join(dir, 'plugins', 'verdaccio-security-filter'), 'dir');

    const config = { ...pluginConfig, cveCheck: pluginConfig.cveCheck && { cacheDir: path.join(dir, 'cve-cache'), ...(pluginConfig.cveCheck as object) } };
    const app: http.Server = await runServer({
        self_path: path.join(dir, 'config.yaml'),
        configPath: path.join(dir, 'config.yaml'),
        storage: path.join(dir, 'storage'),
        plugins: path.join(dir, 'plugins'),
        auth: { htpasswd: { file: path.join(dir, 'htpasswd') } },
        uplinks: { mock: { url: `http://127.0.0.1:${uplinkPort}` } },
        packages: {
            '@*/*': { access: '$all', publish: '$authenticated', proxy: 'mock' },
            '**': { access: '$all', publish: '$authenticated', proxy: 'mock' },
        },
        // Both layers, as the README tells users to configure it.
        filters: { 'security-filter': config },
        middlewares: { 'security-filter': config },
        log: { type: 'stdout', format: 'json', level: 'fatal' },
    });
    const port = await listen(app);

    const request = async (method: string, urlPath: string, body?: unknown) => {
        const response = await realFetch(`http://127.0.0.1:${port}${urlPath}`, {
            method,
            headers: body ? { 'content-type': 'application/json' } : undefined,
            body: body ? JSON.stringify(body) : undefined,
        });
        const text = await response.text();
        try {
            return { status: response.status, body: JSON.parse(text) };
        } catch {
            return { status: response.status, body: text };
        }
    };

    return {
        request,
        get: urlPath => request('GET', urlPath),
        async stop() {
            await Promise.all([close(app), close(uplink)]);
            fs.rmSync(dir, { recursive: true, force: true });
        },
    };
}

const versionsOf = (response: { body: any }) => Object.keys(response.body.versions || {});

describe('plugin inside a running Verdaccio', () => {
    let registry: Registry;

    beforeAll(() => {
        // The plugin calls OSV through global fetch; everything else goes to the real one.
        global.fetch = ((input: any, init?: any) => {
            if (String(input?.url ?? input).startsWith(OSV_URL)) {
                osvCalls++;
                return osvHandler();
            }
            return realFetch(input, init);
        }) as typeof fetch;
    });

    afterAll(() => {
        global.fetch = realFetch;
    });

    beforeEach(() => {
        osvCalls = 0;
        osvHandler = async () => Response.json({ vulns: [] });
    });

    afterEach(async () => {
        await registry?.stop();
    });

    describe('blacklist rules', () => {
        beforeEach(async () => {
            registry = await startRegistry({
                mode: 'blacklist',
                blockedVersions: ['demo-pkg@1.5.0'],
                versionRangeRules: [{ package: 'demo-pkg', range: '<1.5.0', strategy: 'block' }],
                blockedPatterns: ['^evil-'],
                blockedScopes: ['@bad'],
            });
        });

        it('serves an unrestricted package untouched', async () => {
            const metadata = await registry.get('/other-pkg');

            expect(metadata.status).toBe(200);
            expect(versionsOf(metadata)).toEqual(VERSIONS);
            expect(metadata.body['dist-tags']).toEqual({ latest: '2.0.0' });
        });

        it('hides versions blocked by blockedVersions and versionRangeRules, and refuses their tarballs', async () => {
            const metadata = await registry.get('/demo-pkg');
            expect(versionsOf(metadata)).toEqual(['2.0.0']);

            for (const version of ['1.0.0', '1.5.0']) {
                const tarball = await registry.get(`/demo-pkg/-/demo-pkg-${version}.tgz`);
                expect(tarball.status).toBe(403);
                expect(tarball.body).toEqual(expect.objectContaining({ error: 'Package blocked by security filter', version }));
            }

            const allowed = await registry.get('/demo-pkg/-/demo-pkg-2.0.0.tgz');
            expect(allowed.status).toBe(200);
            expect(allowed.body).toBe('fake tarball');
        });

        it('blocks a package by name pattern', async () => {
            const metadata = await registry.get('/evil-pkg');
            expect(versionsOf(metadata)).toEqual([]);
            expect(metadata.body.security).toEqual(expect.objectContaining({ blocked: true }));

            expect((await registry.get('/evil-pkg/-/evil-pkg-1.0.0.tgz')).status).toBe(403);
        });

        it.each(['/@bad/pkg', '/@bad%2fpkg'])('blocks a scoped package requested as %s', async (urlPath) => {
            const metadata = await registry.get(urlPath);
            expect(versionsOf(metadata)).toEqual([]);
            expect(metadata.body.security).toEqual(expect.objectContaining({ blocked: true }));

            expect((await registry.get('/@bad/pkg/-/pkg-1.0.0.tgz')).status).toBe(403);
        });
    });

    describe('whitelist mode', () => {
        beforeEach(async () => {
            registry = await startRegistry({ mode: 'whitelist', whitelist: { packages: ['demo-pkg'], patterns: [] } });
        });

        it('serves whitelisted packages and blocks everything else', async () => {
            expect(versionsOf(await registry.get('/demo-pkg'))).toEqual(VERSIONS);
            expect((await registry.get('/demo-pkg/-/demo-pkg-1.0.0.tgz')).status).toBe(200);

            const blocked = await registry.get('/other-pkg');
            expect(versionsOf(blocked)).toEqual([]);
            expect(blocked.body.security).toEqual(expect.objectContaining({ blocked: true }));
            expect((await registry.get('/other-pkg/-/other-pkg-1.0.0.tgz')).status).toBe(403);
        });

        it('leaves Verdaccio API routes and publish requests to Verdaccio', async () => {
            expect((await registry.get('/-/ping')).status).toBe(200);

            // Anonymous publish of a non-whitelisted name: Verdaccio must be the one refusing it.
            const publish = await registry.request('PUT', '/other-pkg', { name: 'other-pkg', versions: {}, _attachments: {} });
            expect([401, 403]).toContain(publish.status);
            expect(JSON.stringify(publish.body)).not.toContain('security filter');
        });
    });

    describe('whitelist version constraints', () => {
        it('lists only versions inside whitelist.versions and refuses the other tarballs', async () => {
            registry = await startRegistry({
                mode: 'whitelist',
                whitelist: { packages: ['demo-pkg'], patterns: [], versions: { 'demo-pkg': '^1.0.0' } },
            });

            const metadata = await registry.get('/demo-pkg');
            expect(versionsOf(metadata)).toEqual(['1.0.0', '1.5.0']);
            // The plugin drops the dist-tag of a removed version; Verdaccio then points `latest`
            // at the highest version that is left.
            expect(metadata.body['dist-tags']).toEqual({ latest: '1.5.0' });

            expect((await registry.get('/demo-pkg/-/demo-pkg-1.5.0.tgz')).status).toBe(200);
            expect((await registry.get('/demo-pkg/-/demo-pkg-2.0.0.tgz')).status).toBe(403);
        });
    });

    describe('license check', () => {
        it('removes only the versions with a disallowed license', async () => {
            registry = await startRegistry({ mode: 'blacklist', licenses: { allowed: ['MIT'], blocked: [], requireLicense: true } });

            const metadata = await registry.get('/demo-pkg');

            expect(versionsOf(metadata)).toEqual(['1.5.0', '2.0.0']);
            expect(metadata.body['dist-tags']).toEqual({ latest: '2.0.0' });
        });
    });

    describe('CVE check', () => {
        const fixedIn2 = {
            id: 'GHSA-e2e',
            database_specific: { severity: 'HIGH' },
            affected: [{ package: { name: 'demo-pkg' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] }],
        };
        const cveCheck = { enabled: true, autoBlock: true, severity: ['high', 'critical'] };

        it('removes only the vulnerable versions and asks OSV once per package', async () => {
            osvHandler = async () => Response.json({ vulns: [fixedIn2] });
            registry = await startRegistry({ mode: 'blacklist', cveCheck });

            expect(versionsOf(await registry.get('/demo-pkg'))).toEqual(['2.0.0']);
            expect(versionsOf(await registry.get('/demo-pkg'))).toEqual(['2.0.0']);
            expect(osvCalls).toBe(1);
        });

        it('lets Verdaccio re-point latest when the latest version is the vulnerable one', async () => {
            osvHandler = async () => Response.json({ vulns: [{
                id: 'GHSA-e2e-latest',
                database_specific: { severity: 'HIGH' },
                affected: [{ ranges: [{ type: 'SEMVER', events: [{ introduced: '2.0.0' }] }] }],
            }] });
            registry = await startRegistry({ mode: 'blacklist', cveCheck });

            const metadata = await registry.get('/demo-pkg');

            // The plugin drops the dist-tag; Verdaccio points latest at the highest version left.
            expect(versionsOf(metadata)).toEqual(['1.0.0', '1.5.0']);
            expect(metadata.body['dist-tags']).toEqual({ latest: '1.5.0' });
        });

        it('serves the package unchecked when OSV is down and onCveCheckError is fail-open', async () => {
            osvHandler = async () => { throw new Error('OSV down'); };
            registry = await startRegistry({ mode: 'blacklist', cveCheck, errorHandling: { onCveCheckError: 'fail-open' } });

            expect(versionsOf(await registry.get('/demo-pkg'))).toEqual(VERSIONS);
        });

        it('blocks the package when OSV is down and onCveCheckError is fail-closed', async () => {
            osvHandler = async () => { throw new Error('OSV down'); };
            registry = await startRegistry({ mode: 'blacklist', cveCheck, errorHandling: { onCveCheckError: 'fail-closed' } });

            const metadata = await registry.get('/demo-pkg');
            // Verdaccio drops the `security` field that filter_metadata adds, so only the
            // empty version list reaches the client for blocks decided in the filter layer.
            expect(versionsOf(metadata)).toEqual([]);
            expect(metadata.body['dist-tags']).toEqual({});
        });
    });
});
