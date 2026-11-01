// Load environment variables before importing services that read them.
import 'dotenv/config';
import { createHash } from 'node:crypto';
import express from 'express';
import cors from 'cors';

import { preprocessInput } from './services/preprocessing.js';
import { checkMetadata } from './services/metadata.js';
import { analyzeWithQwen, QwenEngineError } from './services/qwenEngine.js';
import {
  connectDatabase,
  disconnectDatabase,
  prisma,
} from './config/prisma.js';
import {
  connectRedis,
  getCachedJson,
  isRedisReady,
  quitRedis,
  setCachedJson,
} from './config/redis.js';

const CACHE_KEY_PREFIX = 'scan:';
const CACHE_TTL_SECONDS = 86_400;

const app = express();

// Global middleware
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

function hashContent(content) {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

function cacheKeyFor(hash) {
  return `${CACHE_KEY_PREFIX}${hash}`;
}

let cacheBypassWarningLogged = false;

function logCacheBypass(reason) {
  if (cacheBypassWarningLogged) {
    return;
  }

  cacheBypassWarningLogged = true;
  console.warn(`[cache] Redis unavailable, bypassing cache: ${reason}`);
}

async function persistScanReport({ hash, rawContent, inputType, verdict }) {
  try {
    await prisma.scanReport.upsert({
      where: { contentHash: hash },
      create: {
        contentHash: hash,
        rawContent,
        inputType,
        riskLevel: verdict.risk_level,
        redFlags: JSON.stringify(verdict.red_flags),
        explanation: verdict.explanation,
        actionableGuidance: JSON.stringify(verdict.actionable_guidance),
      },
      update: {
        rawContent,
        inputType,
        riskLevel: verdict.risk_level,
        redFlags: JSON.stringify(verdict.red_flags),
        explanation: verdict.explanation,
        actionableGuidance: JSON.stringify(verdict.actionable_guidance),
      },
    });

    return true;
  } catch (error) {
    console.warn(
      `[database] could not persist ScanReport ${hash.slice(0, 12)}: ${error.message}`,
    );
    return false;
  }
}

function fallbackMetadataError(error) {
  return {
    success: false,
    skipped: true,
    degraded: true,
    checkedAt: new Date().toISOString(),
    domains: [],
    flags: [],
    errors: [
      {
        code: 'METADATA_CHECK_FAILED',
        message: error?.message || 'Layer 2 metadata checks failed.',
      },
    ],
    summary: {
      domainCount: 0,
      highRiskDomains: 0,
      mediumRiskDomains: 0,
      truncated: false,
    },
  };
}

// -----------------------------------------------------------------------------
// Routes
// -----------------------------------------------------------------------------

// Health check
app.get('/', (_req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'phishguard-backend',
    timestamp: new Date().toISOString(),
  });
});

/**
 * POST /api/analyze
 * Body: { inputType: string, content: string }
 *
 * Pipeline:
 *   Layer 0: Redis cache lookup by SHA-256 content hash
 *   Layer 1: input preprocessing
 *   Layer 2: domain metadata / RDAP checks
 *   Layer 3: Qwen analysis
 *   Persistence: SQLite ScanReport + Redis SETEX cache write
 */
app.post('/api/analyze', async (req, res, next) => {
  const { inputType, content } = req.body ?? {};

  if (typeof inputType !== 'string' || typeof content !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Request body must include string "inputType" and "content".',
    });
  }

  const hash = hashContent(content);
  const cacheKey = cacheKeyFor(hash);
  let cacheState = 'MISS';

  // Layer 0: cache lookup. Redis is optional; every failure is non-fatal.
  try {
    if (!isRedisReady()) {
      cacheState = 'BYPASS';
      logCacheBypass('client is not ready');
    } else {
      const cachedResponse = await getCachedJson(cacheKey);

      if (cachedResponse) {
        res.set('X-Cache', 'HIT');
        return res.status(200).json({
          ...cachedResponse,
          cached: true,
          layers: {
            ...(cachedResponse.layers ?? {}),
            layer0: 'hit',
          },
          cache: {
            ...(cachedResponse.cache ?? {}),
            status: 'HIT',
            hit: true,
          },
        });
      }
    }
  } catch (error) {
    cacheState = 'BYPASS';
    logCacheBypass(error?.message || 'cache lookup failed');
  }

  res.set('X-Cache', cacheState);

  // Layer 1: preprocessing.
  const layer1 = preprocessInput(inputType, content);

  if (!layer1.success) {
    return res.status(400).json({
      success: false,
      stage: 'layer1_preprocessing',
      error: layer1.error,
      metadata: layer1.metadata,
    });
  }

  // Layer 2: metadata checks. checkMetadata is designed to degrade internally,
  // but keep this guard so an unexpected failure cannot kill the request.
  let metadataChecks;
  try {
    metadataChecks = await checkMetadata(layer1.cleanedText);
  } catch (error) {
    console.warn(`[metadata] Layer 2 failed: ${error.message}`);
    metadataChecks = fallbackMetadataError(error);
  }

  // Layer 3: Qwen verdict, with metadata context and a deterministic risk floor.
  let verdict;
  try {
    verdict = await analyzeWithQwen(layer1.cleanedText, metadataChecks);
  } catch (error) {
    if (error instanceof QwenEngineError) {
      const status =
        error.code === 'OLLAMA_UNAVAILABLE' || error.code === 'MODEL_NOT_FOUND'
          ? 503
          : 502;

      return res.status(status).json({
        success: false,
        stage: 'layer3_qwen',
        code: error.code,
        error: error.message,
      });
    }

    return next(error);
  }

  // Persistence: best-effort SQLite write.
  const persisted = await persistScanReport({
    hash,
    rawContent: content,
    inputType: layer1.metadata.inputType,
    verdict,
  });

  const responsePayload = {
    success: true,
    cached: false,
    input: {
      inputType: layer1.metadata.inputType,
      contentHash: hash,
    },
    preprocessing: {
      cleanedText: layer1.cleanedText,
      metadata: layer1.metadata,
    },
    metadataChecks,
    verdict,
    layers: {
      layer0: cacheState === 'BYPASS' ? 'bypassed' : 'miss',
      layer1: 'completed',
      layer2: metadataChecks.degraded ? 'completed_degraded' : 'completed',
      layer3: 'completed',
    },
    persistence: {
      saved: persisted,
    },
    cache: {
      status: 'MISS',
      ttlSeconds: CACHE_TTL_SECONDS,
      stored: false,
    },
  };

  // Cache the completed response. Failures are non-fatal.
  try {
    const cached = await setCachedJson(
      cacheKey,
      responsePayload,
      CACHE_TTL_SECONDS,
    );

    responsePayload.cache.stored = cached;
    responsePayload.cache.status = cached
      ? 'MISS'
      : cacheState === 'BYPASS'
        ? 'BYPASS'
        : 'WRITE_FAILED';
  } catch (error) {
    responsePayload.cache.status = 'WRITE_FAILED';
    console.warn(`[cache] could not store ${cacheKey}: ${error.message}`);
  }

  return res.status(200).json(responsePayload);
});

// 404 fallback
app.use((req, res) => {
  res.status(404).json({ success: false, error: `Route not found: ${req.originalUrl}` });
});

// Centralized error handler
app.use((err, _req, res, _next) => {
  console.error('[phishguard] Unhandled error:', err);
  res.status(500).json({ success: false, error: 'Internal server error.' });
});

const PORT = process.env.PORT || 5000;

connectRedis().then((connected) => {
  if (!connected) {
    logCacheBypass('initial connection failed');
  }
});

connectDatabase();

const server = app.listen(PORT, () => {
  console.log(`Server is successfully running on http://localhost:${PORT}`);
});

async function shutdown(signal) {
  console.log(`[phishguard] ${signal} received, shutting down.`);
  server.close(async () => {
    await Promise.allSettled([disconnectDatabase(), quitRedis()]);
    process.exit(0);
  });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

export default app;
