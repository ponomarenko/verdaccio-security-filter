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

    it('records removed versions as one event and does not repeat it within the window', () => {
        collector = new MetricsCollector({ enabled: true, output: 'stdout' });
        const now = Date.now();
        const clock = jest.spyOn(Date, 'now').mockReturnValue(now);

        collector.recordFiltered('lodash', ['1.0.0', '2.0.0'], 'Package has 2 vulnerable version(s)');
        collector.recordFiltered('lodash', ['1.0.0', '2.0.0'], 'Package has 2 vulnerable version(s)'); // same request pattern
        collector.recordFiltered('lodash', ['1.0.0'], 'Version too new');                                // different removal
        collector.recordFiltered('lodash', [], 'nothing removed');
        collector.flush();

        const events = logSpy.mock.calls.map(call => JSON.parse(call[0]));
        expect(events).toHaveLength(2);
        expect(events[0]).toEqual(expect.objectContaining({ event: 'block', packageName: 'lodash', metadata: { versions: ['1.0.0', '2.0.0'] } }));
        expect(events[0].version).toBeUndefined();

        clock.mockReturnValue(now + 11 * 60 * 1000);
        collector.recordFiltered('lodash', ['1.0.0', '2.0.0'], 'Package has 2 vulnerable version(s)');
        collector.flush();
        expect(logSpy).toHaveBeenCalledTimes(3);
    });

    it('keeps summary counters across flushes', () => {
        collector = new MetricsCollector({ enabled: true, output: 'stdout' });
        collector.recordBlock('a', '1.0.0', 'reason');
        collector.flush();
        collector.recordBlock('b', '*', 'reason');
        collector.recordFiltered('c', ['1.0.0'], 'reason', 'author_blocked');

        expect(collector.getSummary()).toEqual({ block: 2, author_blocked: 1 });
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
