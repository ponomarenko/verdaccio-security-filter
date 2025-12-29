import * as fs from 'fs';
import * as path from 'path';
import { MetricsConfig, MetricsData } from '../types';

/**
 * Metrics collector for tracking security events
 */
export class MetricsCollector {
    private config: MetricsConfig;
    private metricsBuffer: MetricsData[] = [];
    private readonly bufferSize = 100;
    private readonly maxBufferSize = 500;

    constructor(config?: MetricsConfig) {
        this.config = {
            enabled: config?.enabled || false,
            output: config?.output || 'stdout',
            filePath: config?.filePath || './security-metrics.json',
        };
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

        this.metricsBuffer.push(event);

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
     * Record a fallback event
     */
    recordFallback(packageName: string, fromVersion: string, toVersion: string, reason: string): void {
        this.record({
            timestamp: new Date().toISOString(),
            event: 'fallback',
            packageName,
            version: fromVersion,
            reason,
            metadata: { toVersion },
        });
    }

    /**
     * Record a publish rejection
     */
    recordPublishRejected(packageName: string, version: string, reason: string): void {
        this.record({
            timestamp: new Date().toISOString(),
            event: 'publish_rejected',
            packageName,
            version,
            reason,
        });
    }

    /**
     * Record a CVE detection
     */
    recordCVE(packageName: string, version: string, cveId: string, severity: string): void {
        this.record({
            timestamp: new Date().toISOString(),
            event: 'cve_detected',
            packageName,
            version,
            reason: `CVE ${cveId} (${severity})`,
            metadata: { cveId, severity },
        });
    }

    /**
     * Record a license block
     */
    recordLicenseBlock(packageName: string, version: string, license: string, reason: string): void {
        this.record({
            timestamp: new Date().toISOString(),
            event: 'license_blocked',
            packageName,
            version,
            reason,
            metadata: { license },
        });
    }

    /**
     * Record a package-too-new event
     */
    recordPackageTooNew(packageName: string, version: string, reason: string, metadata?: Record<string, any>): void {
        this.record({
            timestamp: new Date().toISOString(),
            event: 'package_too_new',
            packageName,
            version,
            reason,
            metadata,
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
            console.error('[Security Filter] Failed to write metrics:', message);
        }
    }

    /**
     * Get metrics summary
     */
    getSummary(): Record<string, number> {
        const summary: Record<string, number> = {
            block: 0,
            fallback: 0,
            publish_rejected: 0,
            cve_detected: 0,
            license_blocked: 0,
            package_too_new: 0,
            author_blocked: 0,
        };

        this.metricsBuffer.forEach(metric => {
            summary[metric.event] = (summary[metric.event] || 0) + 1;
        });

        return summary;
    }

    /**
     * Cleanup - flush remaining metrics
     */
    cleanup(): void {
        this.flush();
    }
}
