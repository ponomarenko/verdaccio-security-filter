import * as fs from 'fs';
import * as path from 'path';
import { MetricsConfig, MetricsData } from '../types';
import { CheckerLog } from './logger';
import { LRUCache } from './lru-cache';

/**
 * Metrics collector for tracking security events
 */
export class MetricsCollector {
    private config: MetricsConfig;
    private metricsBuffer: MetricsData[] = [];
    private readonly bufferSize = 100;
    private readonly maxBufferSize = 500;
    private readonly flushIntervalMs = 10_000;
    private flushTimer: NodeJS.Timeout | null = null;
    private readonly filteredRepeatMs = 10 * 60 * 1000;
    private recentlyFiltered = new LRUCache<string, number>(5000);
    private counts: Record<string, number> = { block: 0, author_blocked: 0 };

    constructor(config?: MetricsConfig, private readonly dryRun = false, private readonly log: CheckerLog = console) {
        this.config = {
            enabled: config?.enabled || false,
            output: config?.output || 'stdout',
            filePath: config?.filePath || './security-metrics.json',
        };

        if (this.config.enabled) {
            // Verdaccio never calls destroy(), so without this a quiet registry keeps events in memory forever.
            this.flushTimer = setInterval(() => this.flush(), this.flushIntervalMs);
            this.flushTimer.unref();
        }
    }

    /**
     * Record a security event
     */
    record(event: MetricsData): void {
        if (!this.config.enabled) {
            return;
        }

        if (this.metricsBuffer.length >= this.maxBufferSize) {
            this.flush();
        }

        this.counts[event.event] = (this.counts[event.event] || 0) + 1;
        this.metricsBuffer.push(this.dryRun ? { ...event, dryRun: true } : event);

        if (this.metricsBuffer.length >= this.bufferSize) {
            this.flush();
        }
    }

    /**
     * Record a block event
     */
    recordBlock(packageName: string, version: string, reason: string, metadata?: Record<string, any>): void {
        this.record({
            timestamp: new Date().toISOString(),
            event: 'block',
            packageName,
            version,
            reason,
            metadata,
        });
    }

    /**
     * Record versions removed from a package's metadata as ONE event (the versions are in
     * metadata.versions). Metadata is filtered on every request, so the same removal is
     * recorded at most once per repeat window instead of once per version per request.
     */
    recordFiltered(
        packageName: string,
        versions: string[],
        reason: string,
        event: MetricsData['event'] = 'block',
        metadata: Record<string, any> = {},
    ): void {
        if (!this.config.enabled || versions.length === 0) {
            return;
        }

        const key = `${event}|${packageName}|${reason}|${versions.join(',')}`;
        const now = Date.now();
        if (now - (this.recentlyFiltered.get(key) ?? -Infinity) < this.filteredRepeatMs) {
            return;
        }
        this.recentlyFiltered.set(key, now);

        this.record({
            timestamp: new Date().toISOString(),
            event,
            packageName,
            reason,
            metadata: { ...metadata, versions },
        });
    }

    /**
     * Flush metrics buffer to output
     */
    flush(): void {
        if (this.metricsBuffer.length === 0) {
            return;
        }

        if (this.config.output === 'stdout') {
            this.metricsBuffer.forEach(metric => {
                // Intentionally the raw console: with output 'stdout' the JSON lines are the product.
                console.log(JSON.stringify(metric));
            });
        } else if (this.config.output === 'file' && this.config.filePath) {
            this.writeToFile(this.metricsBuffer);
        }

        this.metricsBuffer = [];
    }

    /**
     * Write metrics to file
     */
    private writeToFile(metrics: MetricsData[]): void {
        try {
            const filePath = this.config.filePath!;
            const dir = path.dirname(filePath);

            // Ensure directory exists
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }

            // Append to file
            const content = metrics.map(m => JSON.stringify(m)).join('\n') + '\n';
            fs.appendFileSync(filePath, content, 'utf8');
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            this.log.error(`Failed to write metrics: ${message}`);
        }
    }

    /**
     * Number of events recorded since start-up, by event type.
     */
    getSummary(): Record<string, number> {
        return { ...this.counts };
    }

    /**
     * Cleanup - flush remaining metrics
     */
    cleanup(): void {
        if (this.flushTimer) {
            clearInterval(this.flushTimer);
            this.flushTimer = null;
        }
        this.flush();
    }
}
