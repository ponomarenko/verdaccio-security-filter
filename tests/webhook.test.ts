import * as http from 'http';
import { AddressInfo } from 'net';
import { WebhookNotifier, expandEnv, formatSlackText } from '../src/lib/webhook';
import { MetricsCollector } from '../src/lib/metrics';
import { MetricsData } from '../src/types';

const HOOK_URL = 'https://hooks.example.com/services/T000/B000/secret-token';

function blockEvent(overrides: Partial<MetricsData> = {}): MetricsData {
    return {
        timestamp: '2026-01-15T10:30:00.000Z',
        event: 'block',
        packageName: 'lodash',
        version: '4.17.20',
        reason: 'Exact version match in blocklist',
        ...overrides,
    };
}

function response(status: number): Response {
    return new Response(null, { status });
}

describe('WebhookNotifier', () => {
    let fetchMock: jest.SpyInstance;
    let log: { debug: jest.Mock; warn: jest.Mock; error: jest.Mock };

    const sentBodies = () => fetchMock.mock.calls.map(call => JSON.parse(call[1].body));

    beforeEach(() => {
        fetchMock = jest.spyOn(global, 'fetch').mockImplementation(async () => response(200));
        log = { debug: jest.fn(), warn: jest.fn(), error: jest.fn() };
    });

    afterEach(() => {
        jest.useRealTimers();
        jest.restoreAllMocks();
    });

    describe('configuration', () => {
        it('is off without configuration or when disabled', async () => {
            for (const config of [undefined, { enabled: false, url: HOOK_URL }]) {
                const notifier = new WebhookNotifier(config, '1.0.0', log);
                notifier.notify(blockEvent());
                await notifier.flush();

                expect(notifier.enabled).toBe(false);
            }
            expect(fetchMock).not.toHaveBeenCalled();
            expect(log.error).not.toHaveBeenCalled();
        });

        it.each([
            ['a missing URL', { enabled: true, url: '' }, 'webhook.url is not set'],
            ['an invalid URL', { enabled: true, url: 'not a url' }, 'webhook.url is not a valid URL'],
            ['a non-http URL', { enabled: true, url: 'file:///etc/passwd' }, 'webhook.url must be an http(s) URL'],
            ['an unset variable', { enabled: true, url: 'https://example.com/${MISSING_TOKEN}' }, 'environment variable MISSING_TOKEN is not set'],
        ])('disables itself and says why for %s', (_name, config, message) => {
            const notifier = new WebhookNotifier(config, '1.0.0', log, {});

            expect(notifier.enabled).toBe(false);
            expect(log.error).toHaveBeenCalledWith(`Webhook notifications are disabled: ${message}`);
        });

        it('takes secrets from the environment for the URL and the headers', async () => {
            const notifier = new WebhookNotifier({
                enabled: true,
                url: 'https://hooks.example.com/${HOOK_PATH}',
                headers: { Authorization: 'Bearer ${HOOK_TOKEN}' },
            }, '1.2.3', log, { HOOK_PATH: 'abc', HOOK_TOKEN: 's3cret' });

            notifier.notify(blockEvent());
            await notifier.flush();

            const [url, init] = fetchMock.mock.calls[0];
            expect(url).toBe('https://hooks.example.com/abc');
            expect(init.method).toBe('POST');
            expect(init.headers).toEqual({
                'Content-Type': 'application/json',
                'User-Agent': 'verdaccio-security-filter/1.2.3',
                Authorization: 'Bearer s3cret',
            });
        });

        it('never puts the URL in a log message', async () => {
            fetchMock.mockImplementation(async () => response(404));
            const notifier = new WebhookNotifier({ enabled: true, url: HOOK_URL }, '1.0.0', log);
            notifier.notify(blockEvent());
            await notifier.flush();

            const messages = [...log.debug.mock.calls, ...log.warn.mock.calls, ...log.error.mock.calls].flat().join('\n');
            expect(notifier.destination).toBe('hooks.example.com (json)');
            expect(messages).toContain('hooks.example.com');
            expect(messages).not.toContain('secret-token');
        });
    });

    describe('delivery', () => {
        it('collects events for a few seconds and sends them as one request', async () => {
            jest.useFakeTimers();
            const notifier = new WebhookNotifier({ enabled: true, url: HOOK_URL }, '1.2.3', log);

            notifier.notify(blockEvent({ packageName: 'a' }));
            notifier.notify(blockEvent({ packageName: 'b' }));
            expect(fetchMock).not.toHaveBeenCalled();

            await jest.advanceTimersByTimeAsync(5_000);

            expect(fetchMock).toHaveBeenCalledTimes(1);
            expect(sentBodies()[0]).toEqual({
                source: 'verdaccio-security-filter',
                version: '1.2.3',
                sentAt: expect.any(String),
                events: [blockEvent({ packageName: 'a' }), blockEvent({ packageName: 'b' })],
            });
        });

        it('sends a full batch without waiting', async () => {
            const notifier = new WebhookNotifier({ enabled: true, url: HOOK_URL }, '1.0.0', log);
            for (let i = 0; i < 120; i++) {
                notifier.notify(blockEvent({ packageName: `pkg-${i}` }));
            }
            await notifier.flush();

            expect(sentBodies().map(body => body.events.length)).toEqual([50, 50, 20]);
        });

        it('sends the same event once per repeat interval', async () => {
            const now = Date.now();
            const clock = jest.spyOn(Date, 'now').mockReturnValue(now);
            const notifier = new WebhookNotifier({ enabled: true, url: HOOK_URL, repeatIntervalMinutes: 30 }, '1.0.0', log);

            notifier.notify(blockEvent());
            notifier.notify(blockEvent({ timestamp: 'later' }));       // same block, requested again
            notifier.notify(blockEvent({ version: '4.17.21' }));       // another version
            notifier.notify(blockEvent({ dryRun: true }));             // simulated, not the same thing
            notifier.notify(blockEvent({ version: undefined, metadata: { versions: ['1.0.0', '2.0.0'] } }));
            notifier.notify(blockEvent({ version: undefined, metadata: { versions: ['1.0.0', '2.0.0'] } }));
            await notifier.flush();
            expect(sentBodies()[0].events).toHaveLength(4);

            clock.mockReturnValue(now + 29 * 60_000);
            notifier.notify(blockEvent());
            await notifier.flush();
            expect(fetchMock).toHaveBeenCalledTimes(1);

            clock.mockReturnValue(now + 31 * 60_000);
            notifier.notify(blockEvent());
            await notifier.flush();
            expect(fetchMock).toHaveBeenCalledTimes(2);
        });

        it('sends every occurrence when repeatIntervalMinutes is 0', async () => {
            const notifier = new WebhookNotifier({ enabled: true, url: HOOK_URL, repeatIntervalMinutes: 0 }, '1.0.0', log);
            notifier.notify(blockEvent());
            notifier.notify(blockEvent());
            await notifier.flush();

            expect(sentBodies()[0].events).toHaveLength(2);
        });

        it('retries server errors and rate limits, then delivers', async () => {
            jest.useFakeTimers();
            fetchMock
                .mockImplementationOnce(async () => response(503))
                .mockImplementationOnce(async () => response(429))
                .mockImplementationOnce(async () => response(200));
            const notifier = new WebhookNotifier({ enabled: true, url: HOOK_URL }, '1.0.0', log);

            notifier.notify(blockEvent());
            const done = notifier.flush();
            await jest.advanceTimersByTimeAsync(5_000);
            await done;

            expect(fetchMock).toHaveBeenCalledTimes(3);
            expect(log.warn).not.toHaveBeenCalled();
        });

        it('gives up after three attempts, drops the batch and reports the event again next time', async () => {
            jest.useFakeTimers();
            fetchMock.mockImplementation(async () => {
                throw new Error('connect ECONNREFUSED');
            });
            const notifier = new WebhookNotifier({ enabled: true, url: HOOK_URL }, '1.0.0', log);

            notifier.notify(blockEvent());
            const done = notifier.flush();
            await jest.advanceTimersByTimeAsync(5_000);
            await done;

            expect(fetchMock).toHaveBeenCalledTimes(3);
            expect(log.warn).toHaveBeenCalledWith(
                'Webhook delivery to hooks.example.com failed, 1 event(s) dropped: connect ECONNREFUSED',
            );

            // Not treated as a repeat: the endpoint never received it.
            fetchMock.mockImplementation(async () => response(200));
            notifier.notify(blockEvent());
            await notifier.flush();
            expect(fetchMock).toHaveBeenCalledTimes(4);
        });

        it('does not retry a request the endpoint rejects', async () => {
            fetchMock.mockImplementation(async () => response(400));
            const notifier = new WebhookNotifier({ enabled: true, url: HOOK_URL }, '1.0.0', log);

            notifier.notify(blockEvent());
            await notifier.flush();

            expect(fetchMock).toHaveBeenCalledTimes(1);
            expect(log.warn).toHaveBeenCalledWith('Webhook delivery to hooks.example.com failed, 1 event(s) dropped: HTTP 400');
        });

        it('keeps at most 1000 events for an endpoint that does not answer and reports the loss', async () => {
            let release: (value: Response) => void = () => undefined;
            fetchMock.mockImplementationOnce(() => new Promise<Response>(resolve => {
                release = resolve;
            }));
            const notifier = new WebhookNotifier({ enabled: true, url: HOOK_URL }, '1.0.0', log);

            // The first 50 go out at once and hang; 1100 more arrive while that request is open.
            for (let i = 0; i < 1150; i++) {
                notifier.notify(blockEvent({ packageName: `pkg-${i}` }));
            }
            release(response(200));
            await notifier.flush();

            const bodies = sentBodies();
            expect(bodies.reduce((total, body) => total + body.events.length, 0)).toBe(1050);
            expect(bodies[0].dropped).toBeUndefined();
            expect(bodies[1].dropped).toBe(100);
            expect(bodies[1].events[0].packageName).toBe('pkg-150');
        });

        it('posts to a real HTTP endpoint', async () => {
            fetchMock.mockRestore();
            const received: { headers: http.IncomingHttpHeaders; body: any }[] = [];
            const server = http.createServer((req, res) => {
                let data = '';
                req.on('data', chunk => (data += chunk));
                req.on('end', () => {
                    received.push({ headers: req.headers, body: JSON.parse(data) });
                    res.writeHead(204).end();
                });
            });
            await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));

            try {
                const { port } = server.address() as AddressInfo;
                const notifier = new WebhookNotifier({
                    enabled: true,
                    url: `http://127.0.0.1:${port}/hook`,
                    headers: { 'X-Token': 'abc' },
                }, '1.2.3', log);

                notifier.notify(blockEvent());
                await notifier.flush();

                expect(received).toHaveLength(1);
                expect(received[0].headers['content-type']).toBe('application/json');
                expect(received[0].headers['x-token']).toBe('abc');
                expect(received[0].body.events).toEqual([blockEvent()]);
                expect(log.warn).not.toHaveBeenCalled();
            } finally {
                await new Promise(resolve => server.close(resolve));
            }
        });
    });

    describe('slack format', () => {
        it('posts a text message', async () => {
            const notifier = new WebhookNotifier({ enabled: true, url: HOOK_URL, format: 'slack' }, '1.0.0', log);
            notifier.notify(blockEvent());
            notifier.notify(blockEvent({ packageName: 'evil-pkg', version: '*', reason: 'Package name matches blocked pattern' }));
            notifier.notify(blockEvent({
                version: undefined,
                reason: 'Package has 2 vulnerable version(s)',
                metadata: { versions: ['4.17.19', '4.17.20'] },
                dryRun: true,
            }));
            await notifier.flush();

            expect(sentBodies()[0]).toEqual({
                text: [
                    '*Verdaccio security filter*: 3 event(s)',
                    '• blocked `lodash@4.17.20`: Exact version match in blocklist',
                    '• blocked `evil-pkg`: Package name matches blocked pattern',
                    '• [DRY RUN] would block `lodash` (2 version(s): 4.17.19, 4.17.20): Package has 2 vulnerable version(s)',
                ].join('\n'),
            });
        });

        it('escapes markup in names and reasons taken from requests', () => {
            const text = formatSlackText([blockEvent({ packageName: '<!channel>', version: '*', reason: 'a & b `c`' })]);

            expect(text).toContain("`&lt;!channel&gt;`: a &amp; b 'c'");
        });

        it('shortens long version lists and long batches', () => {
            const versions = Array.from({ length: 14 }, (_, i) => `1.0.${i}`);
            const events = Array.from({ length: 25 }, (_, i) =>
                blockEvent({ packageName: `pkg-${i}`, version: undefined, metadata: { versions } }));

            const lines = formatSlackText(events, 3).split('\n');

            expect(lines).toHaveLength(23);
            expect(lines[1]).toContain('(14 version(s): 1.0.0, 1.0.1, 1.0.2, 1.0.3, 1.0.4, 1.0.5, 1.0.6, 1.0.7, 1.0.8, 1.0.9, +4 more)');
            expect(lines[21]).toBe('…and 5 more event(s)');
            expect(lines[22]).toBe('_3 earlier event(s) were dropped because the webhook was unreachable_');
        });
    });

    describe('expandEnv', () => {
        it('replaces every reference and leaves other text alone', () => {
            expect(expandEnv('https://${HOST}/x/${TOKEN}?a=$b', { HOST: 'h', TOKEN: 't' })).toBe('https://h/x/t?a=$b');
        });

        it('rejects an empty variable', () => {
            expect(() => expandEnv('${TOKEN}', { TOKEN: '' })).toThrow('environment variable TOKEN is not set');
        });
    });

    describe('with MetricsCollector', () => {
        let collector: MetricsCollector;
        let consoleLog: jest.SpyInstance;

        beforeEach(() => {
            consoleLog = jest.spyOn(console, 'log').mockImplementation(() => undefined);
        });

        afterEach(() => collector?.cleanup());

        it('receives events while metrics are disabled', async () => {
            const notifier = new WebhookNotifier({ enabled: true, url: HOOK_URL }, '1.0.0', log);
            collector = new MetricsCollector({ enabled: false }, false, log, notifier);

            collector.recordBlock('evil-pkg', '*', 'Package name matches blocked pattern');
            collector.recordFiltered('lodash', ['1.0.0'], 'Version too new');
            collector.flush();
            await notifier.flush();

            expect(consoleLog).not.toHaveBeenCalled();
            expect(collector.getSummary()).toEqual({ block: 0, author_blocked: 0 });
            expect(sentBodies()[0].events).toEqual([
                expect.objectContaining({ packageName: 'evil-pkg', version: '*' }),
                expect.objectContaining({ packageName: 'lodash', metadata: { versions: ['1.0.0'] } }),
            ]);
        });

        it('marks dry-run events', async () => {
            const notifier = new WebhookNotifier({ enabled: true, url: HOOK_URL }, '1.0.0', log);
            collector = new MetricsCollector({ enabled: true, output: 'stdout' }, true, log, notifier);

            collector.recordBlock('evil-pkg', '*', 'reason');
            collector.flush();
            await notifier.flush();

            expect(sentBodies()[0].events[0].dryRun).toBe(true);
            expect(JSON.parse(consoleLog.mock.calls[0][0]).dryRun).toBe(true);
        });

        it('leaves metrics untouched when no webhook is configured', () => {
            collector = new MetricsCollector({ enabled: true, output: 'stdout' }, false, log, new WebhookNotifier());
            collector.recordBlock('pkg', '1.0.0', 'reason');
            collector.flush();

            expect(consoleLog).toHaveBeenCalledTimes(1);
            expect(fetchMock).not.toHaveBeenCalled();
        });
    });
});
