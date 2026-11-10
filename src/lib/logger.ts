import { Logger } from '@verdaccio/types';
import { LoggerConfig } from '../types';

/**
 * What the checkers need for logging. The plugin passes its SecurityLogger; used on their
 * own (tests, scripts) the checkers fall back to the console, which has the same shape.
 */
export type CheckerLog = Pick<SecurityLogger, 'debug' | 'warn' | 'error'>;

/**
 * Enhanced logger wrapper with configurable log levels and formatting
 */
export class SecurityLogger {
    private verdaccioLogger: Logger;
    private config: LoggerConfig;
    private readonly prefix: string;

    constructor(verdaccioLogger: Logger, config?: LoggerConfig, dryRun = false) {
        // In dry-run every line is marked, so "BLOCKED" in the log cannot be mistaken for a real block.
        this.prefix = dryRun ? '[Security Filter] [DRY RUN]' : '[Security Filter]';
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
     * Log initialization
     */
    logInit(features: string[]): void {
        this.info(`Plugin initialized with features: ${features.join(', ')}`);
    }
}
