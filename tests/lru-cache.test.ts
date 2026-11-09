import { LRUCache } from '../src/lib/lru-cache';

describe('LRUCache', () => {
    it('evicts the least recently used entry when full', () => {
        const cache = new LRUCache<string, number>(2);
        cache.set('a', 1);
        cache.set('b', 2);
        cache.get('a'); // 'b' is now the oldest
        cache.set('c', 3);

        expect(cache.has('b')).toBe(false);
        expect([...cache.entries()]).toEqual([['a', 1], ['c', 3]]);
        expect(cache.size).toBe(2);
    });

    it('overwrites an existing key without evicting another one', () => {
        const cache = new LRUCache<string, number>(2);
        cache.set('a', 1);
        cache.set('b', 2);
        cache.set('a', 10);

        expect(cache.get('a')).toBe(10);
        expect(cache.get('b')).toBe(2);
    });

    it('returns undefined for a missing key and supports delete and clear', () => {
        const cache = new LRUCache<string, number>(2);
        cache.set('a', 1);

        expect(cache.get('missing')).toBeUndefined();
        expect(cache.delete('a')).toBe(true);
        cache.set('b', 2);
        cache.clear();
        expect(cache.size).toBe(0);
    });
});
