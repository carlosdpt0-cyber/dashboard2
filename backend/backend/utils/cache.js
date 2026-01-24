const NodeCache = require('node-cache');

class CacheManager {
    constructor() {
        this.cache = new NodeCache({
            stdTTL: 600, // 10 minutos por padrão
            checkperiod: 120, // Verificar a cada 2 minutos
            useClones: false
        });
    }

    async get(key) {
        return this.cache.get(key);
    }

    async set(key, value, ttl = null) {
        if (ttl) {
            return this.cache.set(key, value, ttl);
        }
        return this.cache.set(key, value);
    }

    async del(key) {
        return this.cache.del(key);
    }

    async flush() {
        return this.cache.flushAll();
    }

    async getOrSet(key, fetchFunction, ttl = null) {
        let value = await this.get(key);
        
        if (value === undefined) {
            value = await fetchFunction();
            await this.set(key, value, ttl);
        }
        
        return value;
    }
}

module.exports = new CacheManager();