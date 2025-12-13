import { Logger } from '@verdaccio/types';
import { LoggerConfig } from '../types';

/**
 * Enhanced logger wrapper with configurable log levels and formatting
 */
export class SecurityLogger {
    private verdaccioLogger: Logger;
    private config: LoggerConfig;
    private readonly prefix = '[Security Filter]';

    constructor(verdaccioLogger: Logger, config?: LoggerConfig) {
        this.verdaccioLogger = verdaccioLogger;
        this.config = {
            level: config?.level || 'info',
            enabled: config?.enabled !== false,
            includeTimestamp: config?.includeTimestamp !== false,
        };
    }

    private shouldLog(level: 'trace' | 'debug' | 'info' | 'warn' | 'error'): boolean {
        if (!this.config.enabled) {
            return false;
        }

        const levels = ['trace', 'debug', 'info', 'warn', 'error'];
        const configLevel = levels.indexOf(this.config.level);
        const messageLevel = levels.indexOf(level);

        return messageLevel >= configLevel;
    }

    private formatMessage(message: string): string {
        const timestamp = this.config.includeTimestamp
            ? `[${new Date().toISOString()}] `
            : '';
        return `${timestamp}${this.prefix} ${message}`;
    }

    trace(message: string, ...args: any[]): void {
        if (this.shouldLog('trace')) {
            this.verdaccioLogger.trace(this.formatMessage(message), ...args);
        }
    }

    debug(message: string, ...args: any[]): void {
        if (this.shouldLog('debug')) {
            this.verdaccioLogger.debug(this.formatMessage(message), ...args);
        }
    }

    info(message: string, ...args: any[]): void {
        if (this.shouldLog('info')) {
            this.verdaccioLogger.info(this.formatMessage(message), ...args);
        }
    }

    warn(message: string, ...args: any[]): void {
        if (this.shouldLog('warn')) {
            this.verdaccioLogger.warn(this.formatMessage(message), ...args);
        }
    }

    error(message: string, ...args: any[]): void {
        if (this.shouldLog('error')) {
            this.verdaccioLogger.error(this.formatMessage(message), ...args);
        }
    }

    /**
     * Log package blocking event
     */
    logBlock(packageName: string, version: string, reason: string): void {
        this.warn(`Blocked ${packageName}@${version} - ${reason}`);
    }

    /**
     * Log fallback event
     */
    logFallback(packageName: string, fromVersion: string, toVersion: string, reason?: string): void {
        const reasonText = reason ? ` (${reason})` : '';
        this.info(`Fallback applied: ${packageName}@${fromVersion} -> ${toVersion}${reasonText}`);
    }

    /**
     * Log CVE detection
     */
    logCVE(packageName: string, version: string, cveId: string, severity: string): void {
        this.warn(`CVE detected: ${cveId} [${severity}] in ${packageName}@${version}`);
    }

    /**
     * Log license violation
     */
    logLicense(packageName: string, version: string, license: string, reason: string): void {
        this.warn(`License violation: ${packageName}@${version} has ${license} - ${reason}`);
    }

    /**
     * Log publish rejection
     */
    logPublishRejected(packageName: string, version: string, reason: string): void {
        this.warn(`Publish rejected: ${packageName}@${version} - ${reason}`);
    }

    /**
     * Log initialization
     */
    logInit(features: string[]): void {
        this.info(`Plugin initialized with features: ${features.join(', ')}`);
    }
}
