/**
 * Redis connection and cache helpers.
 *
 * Redis is an optional acceleration layer: if it is unavailable, cache reads
 * miss and writes are skipped, but the analysis pipeline keeps working.
 */

import Redis from 'ioredis';

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const ERROR_LOG_INTERVAL_MS = 30_000;

let lastErrorLogAt = 0;

const redis = new Redis(REDIS_URL, {
  lazyConnect: true,
  enableOfflineQueue: false,
  maxRetriesPerRequest: 1,
  connectTimeout: 2_000,
  retryStrategy: (attempt) => Math.min(attempt * 250, 5_000),
});

redis.on('ready', () => {
  console.log(`[redis] connected to ${REDIS_URL}`);
});

redis.on('error', (error) => {
  const now = Date.now();
  if (now - lastErrorLogAt >= ERROR_LOG_INTERVAL_MS) {
    lastErrorLogAt = now;
    const reason =
      error?.message || error?.code || 'connection error';
    console.warn(
      `[redis] unavailable, cache disabled: ${reason}. Retrying in the background.`,
    );
  }
});

/**
 * Attempt an initial connection. Failures are non-fatal; ioredis continues
 * retrying in the background.
 */
export async function connectRedis() {
  try {
    await redis.connect();
    return true;
  } catch {
    return false;
  }
}

export function isRedisReady() {
  return redis.status === 'ready';
}

/**
 * Read and parse a JSON cache entry. Returns null on miss, parse failure, or
 * any Redis error.
 */
export async function getCachedJson(key) {
  if (!isRedisReady()) {
    return null;
  }

  try {
    const raw = await redis.get(key);
    if (raw === null) {
      return null;
    }

    try {
      return JSON.parse(raw);
    } catch {
      await redis.del(key).catch(() => {});
      return null;
    }
  } catch {
    return null;
  }
}

/**
 * Store a JSON value with a TTL. Returns false when Redis is unavailable.
 */
export async function setCachedJson(key, value, ttlSeconds) {
  if (!isRedisReady()) {
    return false;
  }

  try {
    await redis.setex(key, ttlSeconds, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

export async function deleteCachedJson(key) {
  if (!isRedisReady()) {
    return false;
  }

  try {
    await redis.del(key);
    return true;
  } catch {
    return false;
  }
}

export async function quitRedis() {
  try {
    if (redis.status === 'ready') {
      await redis.quit();
    } else {
      redis.disconnect();
    }
  } catch {
    redis.disconnect();
  }
}

export default redis;
