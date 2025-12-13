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

        it('should log block events', () => {
            securityLogger.logBlock('lodash', '4.17.20', 'CVE detected');

            expect(mockLogger.warn).toHaveBeenCalledWith(
                expect.stringContaining('Blocked lodash@4.17.20 - CVE detected')
            );
        });

        it('should log fallback events', () => {
            securityLogger.logFallback('lodash', '4.17.20', '4.17.21', 'Security patch');

            expect(mockLogger.info).toHaveBeenCalledWith(
                expect.stringContaining('Fallback applied: lodash@4.17.20 -> 4.17.21')
            );
        });

        it('should log CVE detection', () => {
            securityLogger.logCVE('lodash', '4.17.20', 'CVE-2021-23337', 'high');

            expect(mockLogger.warn).toHaveBeenCalledWith(
                expect.stringContaining('CVE detected: CVE-2021-23337 [high] in lodash@4.17.20')
            );
        });

        it('should log license violations', () => {
            securityLogger.logLicense('some-package', '1.0.0', 'GPL-3.0', 'License not allowed');

            expect(mockLogger.warn).toHaveBeenCalledWith(
                expect.stringContaining('License violation')
            );
        });

        it('should log publish rejections', () => {
            securityLogger.logPublishRejected('test-package', '1.0.0', 'Too large');

            expect(mockLogger.warn).toHaveBeenCalledWith(
                expect.stringContaining('Publish rejected: test-package@1.0.0 - Too large')
            );
        });

        it('should log initialization', () => {
            securityLogger.logInit(['cve-checking', 'license-filtering']);

            expect(mockLogger.info).toHaveBeenCalledWith(
                expect.stringContaining('Plugin initialized with features: cve-checking, license-filtering')
            );
        });
    });
});
