import { MetricsData, WebhookConfig } from '../types';
import { CheckerLog } from './logger';
import { LRUCache } from './lru-cache';

/** Events are collected for this long and sent as one request. */
const BATCH_DELAY_MS = 5_000;
/** A batch this large is sent without waiting for the delay. */
const MAX_BATCH_SIZE = 50;
/** Events waiting for delivery; beyond this the oldest are dropped, so a dead endpoint cannot grow the heap. */
const MAX_QUEUE_SIZE = 1_000;
/** Waits before the second and third delivery attempt. */
const RETRY_DELAYS_MS = [1_000, 4_000];
const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_REPEAT_INTERVAL_MINUTES = 60;
/** Slack shows long messages collapsed; the rest is summarized in one line. */
const SLACK_MAX_LINES = 20;
const SLACK_MAX_VERSIONS = 10;

interface QueuedEvent {
    event: MetricsData;
    key: string;
}

/** Thrown for answers that will not change on a retry (4xx other than 429). */
class PermanentDeliveryError extends Error {}

/**
 * Replace `${NAME}` with the environment variable NAME, so tokens can stay out of config.yaml.
 * Throws when a referenced variable is not set: a half-built URL must not be called.
 */
export function expandEnv(value: string, env: NodeJS.ProcessEnv = process.env): string {
    return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_match, name: string) => {
        const resolved = env[name];
        if (resolved === undefined || resolved === '') {
            throw new Error(`environment variable ${name} is not set`);
        }
        return resolved;
    });
}

/** Package names and reasons come from requests and upstream metadata: keep them from forming Slack markup. */
function escapeSlack(text: string): string {
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/`/g, "'");
}

function describeTarget(event: MetricsData): string {
    const name = escapeSlack(event.packageName);
    const versions: unknown = event.metadata?.versions;

    if (!event.version && Array.isArray(versions)) {
        const shown = versions.slice(0, SLACK_MAX_VERSIONS).map(version => escapeSlack(String(version))).join(', ');
        const more = versions.length > SLACK_MAX_VERSIONS ? `, +${versions.length - SLACK_MAX_VERSIONS} more` : '';
        return `\`${name}\` (${versions.length} version(s): ${shown}${more})`;
    }

    return event.version && event.version !== '*' ? `\`${name}@${escapeSlack(event.version)}\`` : `\`${name}\``;
}

/** Body for Slack incoming webhooks and the services that accept the same format. */
export function formatSlackText(events: MetricsData[], dropped = 0): string {
    const lines = events.slice(0, SLACK_MAX_LINES).map(event => {
        const action = event.dryRun ? '[DRY RUN] would block' : 'blocked';
        return `• ${action} ${describeTarget(event)}: ${escapeSlack(event.reason)}`;
    });

    if (events.length > SLACK_MAX_LINES) {
        lines.push(`…and ${events.length - SLACK_MAX_LINES} more event(s)`);
    }
    if (dropped > 0) {
        lines.push(`_${dropped} earlier event(s) were dropped because the webhook was unreachable_`);
    }

    return [`*Verdaccio security filter*: ${events.length} event(s)`, ...lines].join('\n');
}

/**
 * Sends security events to an HTTP endpoint.
 *
 * Delivery never touches the request path: notify() only queues, and a timer sends the queue
 * as one POST. Failures are logged and the events dropped; nothing here can throw into a filter.
 */
export class WebhookNotifier {
    private readonly url: string | null = null;
    private readonly host: string = '';
    private readonly format: 'json' | 'slack';
    private readonly headers: Record<string, string> = {};
    private readonly timeoutMs: number;
    private readonly repeatMs: number;
    private readonly recent = new LRUCache<string, number>(5000);
    private queue: QueuedEvent[] = [];
    private dropped = 0;
    private timer: NodeJS.Timeout | null = null;
    private draining: Promise<void> | null = null;

    constructor(
        config?: WebhookConfig,
        private readonly pluginVersion = 'unknown',
        private readonly log: CheckerLog = console,
        env: NodeJS.ProcessEnv = process.env,
    ) {
        this.format = config?.format === 'slack' ? 'slack' : 'json';
        this.timeoutMs = config?.timeoutMs && config.timeoutMs > 0 ? config.timeoutMs : DEFAULT_TIMEOUT_MS;
        this.repeatMs = (config?.repeatIntervalMinutes ?? DEFAULT_REPEAT_INTERVAL_MINUTES) * 60_000;

        if (!config?.enabled) {
            return;
        }

        if (config.format && config.format !== 'json' && config.format !== 'slack') {
            this.log.warn(`Unknown webhook format "${config.format}", using "json"`);
        }

        // The URL usually carries the secret, so messages name the option or the host, never the URL.
        try {
            if (!config.url) {
                throw new Error('webhook.url is not set');
            }

            const expanded = expandEnv(config.url, env);
            if (!URL.canParse(expanded)) {
                throw new Error('webhook.url is not a valid URL');
            }

            const url = new URL(expanded);
            if (url.protocol !== 'https:' && url.protocol !== 'http:') {
                throw new Error('webhook.url must be an http(s) URL');
            }

            for (const [name, value] of Object.entries(config.headers || {})) {
                this.headers[name] = expandEnv(String(value), env);
            }

            this.url = url.toString();
            this.host = url.host;
        } catch (error) {
            this.log.error(`Webhook notifications are disabled: ${(error as Error).message}`);
        }
    }

    /** True when the configuration is usable and events will be sent. */
    get enabled(): boolean {
        return this.url !== null;
    }

    /** Where events go, without the path: safe to log. */
    get destination(): string {
        return `${this.host} (${this.format})`;
    }

    /**
     * Queue an event. The same event (package, version(s), reason) is sent once per repeat
     * interval: a blocked package is requested again on every install, the channel needs it once.
     */
    notify(event: MetricsData): void {
        if (!this.enabled) {
            return;
        }

        const versions = event.version ?? (Array.isArray(event.metadata?.versions) ? event.metadata.versions.join(',') : '');
        const key = `${event.event}|${event.packageName}|${versions}|${event.reason}|${event.dryRun ? 'dry' : ''}`;
        const now = Date.now();
        if (this.repeatMs > 0 && now - (this.recent.get(key) ?? -Infinity) < this.repeatMs) {
            return;
        }
        this.recent.set(key, now);

        if (this.queue.length >= MAX_QUEUE_SIZE) {
            this.queue.shift();
            this.dropped++;
        }
        this.queue.push({ event, key });

        if (this.queue.length >= MAX_BATCH_SIZE) {
            void this.flush();
        } else if (!this.timer && !this.draining) {
            // A running drain picks the event up by itself.
            this.timer = setTimeout(() => void this.flush(), BATCH_DELAY_MS);
            this.timer.unref();
        }
    }

    /** Send everything queued now. Resolves when the queue is empty; never rejects. */
    flush(): Promise<void> {
        if (this.timer) {
            clearTimeout(this.timer);
            this.timer = null;
        }

        if (!this.draining) {
            this.draining = this.drain().finally(() => {
                this.draining = null;
            });
        }
        return this.draining;
    }

    /** Stop the timer and send what is left, without waiting for the result. */
    cleanup(): void {
        void this.flush();
    }

    private async drain(): Promise<void> {
        while (this.queue.length > 0) {
            const batch = this.queue.splice(0, MAX_BATCH_SIZE);
            const dropped = this.dropped;
            this.dropped = 0;

            try {
                await this.deliver(batch.map(item => item.event), dropped);
            } catch (error) {
                // Forget the events, so the next occurrence is reported instead of being treated as a repeat.
                batch.forEach(item => this.recent.delete(item.key));
                const message = error instanceof Error ? error.message : String(error);
                this.log.warn(`Webhook delivery to ${this.host} failed, ${batch.length} event(s) dropped: ${message}`);
            }
        }
    }

    private async deliver(events: MetricsData[], dropped: number): Promise<void> {
        const payload = this.format === 'slack'
            ? { text: formatSlackText(events, dropped) }
            : {
                source: 'verdaccio-security-filter',
                version: this.pluginVersion,
                sentAt: new Date().toISOString(),
                ...(dropped > 0 ? { dropped } : {}),
                events,
            };
        const body = JSON.stringify(payload);

        for (let attempt = 0; ; attempt++) {
            try {
                const response = await fetch(this.url!, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'User-Agent': `verdaccio-security-filter/${this.pluginVersion}`,
                        ...this.headers,
                    },
                    body,
                    signal: AbortSignal.timeout(this.timeoutMs),
                });
                // The body is not needed; release the connection.
                await response.body?.cancel().catch(() => undefined);

                if (response.ok) {
                    this.log.debug(`Webhook delivered ${events.length} event(s) to ${this.host}`);
                    return;
                }

                const failure = `HTTP ${response.status}`;
                if (response.status !== 429 && response.status < 500) {
                    throw new PermanentDeliveryError(failure);
                }
                throw new Error(failure);
            } catch (error) {
                if (error instanceof PermanentDeliveryError || attempt >= RETRY_DELAYS_MS.length) {
                    throw error;
                }
                await new Promise<void>(resolve => {
                    setTimeout(resolve, RETRY_DELAYS_MS[attempt]).unref();
                });
            }
        }
    }
}
