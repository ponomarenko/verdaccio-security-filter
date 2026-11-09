import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { MetricsCollector } from '../src/lib/metrics';

describe('MetricsCollector', () => {
    let collector: MetricsCollector;
    let logSpy: jest.SpyInstance;

    beforeEach(() => {
        logSpy = jest.spyOn(console, 'log').mockImplementation(() => undefined);
    });

    afterEach(() => {
        collector?.cleanup();
        jest.useRealTimers();
        jest.restoreAllMocks();
    });

    it('records nothing when disabled', () => {
        collector = new MetricsCollector({ enabled: false });
        collector.recordBlock('pkg', '1.0.0', 'reason');
        collector.flush();

        expect(logSpy).not.toHaveBeenCalled();
    });

    it('flushes buffered events on a timer, without waiting for a full buffer', () => {
        jest.useFakeTimers();
        collector = new MetricsCollector({ enabled: true, output: 'stdout' });
        collector.recordBlock('pkg', '1.0.0', 'reason');
        expect(logSpy).not.toHaveBeenCalled();

        jest.advanceTimersByTime(10_000);

        expect(logSpy).toHaveBeenCalledTimes(1);
        expect(JSON.parse(logSpy.mock.calls[0][0])).toEqual(expect.objectContaining({
            event: 'block', packageName: 'pkg', version: '1.0.0', reason: 'reason',
        }));
    });

    it('flushes as soon as the buffer holds 100 events', () => {
        collector = new MetricsCollector({ enabled: true, output: 'stdout' });
        for (let i = 0; i < 100; i++) {
            collector.recordBlock('pkg', String(i), 'reason');
        }

        expect(logSpy).toHaveBeenCalledTimes(100);
    });

    it('appends JSON lines to the configured file, creating its directory', () => {
        const filePath = path.join(os.tmpdir(), `metrics-test-${Date.now()}-${Math.random()}`, 'metrics.jsonl');
        collector = new MetricsCollector({ enabled: true, output: 'file', filePath });
        collector.recordBlock('a', '1.0.0', 'first');
        collector.flush();
        collector.recordBlock('b', '2.0.0', 'second');
        collector.cleanup();

        const lines = fs.readFileSync(filePath, 'utf8').trim().split('\n').map(line => JSON.parse(line));
        expect(lines.map(line => line.packageName)).toEqual(['a', 'b']);
        fs.rmSync(path.dirname(filePath), { recursive: true, force: true });
    });
});
