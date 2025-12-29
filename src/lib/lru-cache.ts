/**
 * Simple LRU (Least Recently Used) Cache implementation with size limits
 */
export class LRUCache<K, V> {
    private cache: Map<K, V>;
    private readonly maxSize: number;

    constructor(maxSize: number = 1000) {
        this.cache = new Map();
        this.maxSize = maxSize;
    }

    get(key: K): V | undefined {
        if (!this.cache.has(key)) {
            return undefined;
        }

        const value = this.cache.get(key)!;
        this.cache.delete(key);
        this.cache.set(key, value);

        return value;
    }

    set(key: K, value: V): void {
        if (this.cache.has(key)) {
            this.cache.delete(key);
        } else if (this.cache.size >= this.maxSize) {
            const firstKey = this.cache.keys().next().value;
            if (firstKey !== undefined) {
                this.cache.delete(firstKey);
            }
        }

        this.cache.set(key, value);
    }

    has(key: K): boolean {
        return this.cache.has(key);
    }

    delete(key: K): boolean {
        return this.cache.delete(key);
    }

    clear(): void {
        this.cache.clear();
    }

    get size(): number {
        return this.cache.size;
    }

    entries(): IterableIterator<[K, V]> {
        return this.cache.entries();
    }
}
