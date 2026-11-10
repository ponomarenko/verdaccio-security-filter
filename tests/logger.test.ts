import { SecurityLogger } from '../src/lib/logger';
import { Logger } from '@verdaccio/types';

describe('SecurityLogger', () => {
    let mockLogger: Logger;
    let securityLogger: SecurityLogger;

    beforeEach(() => {
        mockLogger = {
            error: jest.fn(),
            info: jest.fn(),
            debug: jest.fn(),
            warn: jest.fn(),
            trace: jest.fn(),
            child: jest.fn(),
            http: jest.fn(),
        } as any;
    });

    describe('log level filtering', () => {
        it('should log all levels when set to debug', () => {
            securityLogger = new SecurityLogger(mockLogger, { level: 'debug', enabled: true });

            securityLogger.debug('debug message');
            securityLogger.info('info message');
            securityLogger.warn('warn message');
            securityLogger.error('error message');

            expect(mockLogger.debug).toHaveBeenCalled();
            expect(mockLogger.info).toHaveBeenCalled();
            expect(mockLogger.warn).toHaveBeenCalled();
            expect(mockLogger.error).toHaveBeenCalled();
        });

        it('should only log info and above when set to info', () => {
            securityLogger = new SecurityLogger(mockLogger, { level: 'info', enabled: true });

            securityLogger.debug('debug message');
            securityLogger.info('info message');
            securityLogger.warn('warn message');

            expect(mockLogger.debug).not.toHaveBeenCalled();
            expect(mockLogger.info).toHaveBeenCalled();
            expect(mockLogger.warn).toHaveBeenCalled();
        });

        it('should only log errors when set to error', () => {
            securityLogger = new SecurityLogger(mockLogger, { level: 'error', enabled: true });

            securityLogger.debug('debug message');
            securityLogger.info('info message');
            securityLogger.warn('warn message');
            securityLogger.error('error message');

            expect(mockLogger.debug).not.toHaveBeenCalled();
            expect(mockLogger.info).not.toHaveBeenCalled();
            expect(mockLogger.warn).not.toHaveBeenCalled();
            expect(mockLogger.error).toHaveBeenCalled();
        });

        it('should not log anything when disabled', () => {
            securityLogger = new SecurityLogger(mockLogger, { level: 'debug', enabled: false });

            securityLogger.debug('debug message');
            securityLogger.info('info message');
            securityLogger.warn('warn message');
            securityLogger.error('error message');

            expect(mockLogger.debug).not.toHaveBeenCalled();
            expect(mockLogger.info).not.toHaveBeenCalled();
            expect(mockLogger.warn).not.toHaveBeenCalled();
            expect(mockLogger.error).not.toHaveBeenCalled();
        });
    });

    describe('message formatting', () => {
        beforeEach(() => {
            securityLogger = new SecurityLogger(mockLogger, {
                level: 'info',
                enabled: true,
                includeTimestamp: false,
            });
        });

        it('should include [Security Filter] prefix', () => {
            securityLogger.info('test message');

            expect(mockLogger.info).toHaveBeenCalledWith(
                expect.stringContaining('[Security Filter]')
            );
        });

        it('should include timestamp when enabled', () => {
            securityLogger = new SecurityLogger(mockLogger, {
                level: 'info',
                enabled: true,
                includeTimestamp: true,
            });

            securityLogger.info('test message');

            expect(mockLogger.info).toHaveBeenCalledWith(
                expect.stringMatching(/\[\d{4}-\d{2}-\d{2}T.*\]/)
            );
        });
    });

    describe('specialized log methods', () => {
        beforeEach(() => {
            securityLogger = new SecurityLogger(mockLogger, { level: 'info', enabled: true });
        });

        it('should log initialization', () => {
            securityLogger.logInit(['cve-checking', 'license-filtering']);

            expect(mockLogger.info).toHaveBeenCalledWith(
                expect.stringContaining('Plugin initialized with features: cve-checking, license-filtering')
            );
        });
    });
});
