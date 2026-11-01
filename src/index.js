// Load environment variables before importing services that read them.
import 'dotenv/config';
import { createHash } from 'node:crypto';
import express from 'express';
import cors from 'cors';
import multer from 'multer';

import { extractTextFromBuffer } from './services/ocr.js';
import { preprocessInput } from './services/preprocessing.js';
import { checkMetadata } from './services/metadata.js';
import {
  analyzeWithQwen,
  getIndiaScamDataset,
  QwenEngineError,
} from './services/qwenEngine.js';
import {
  deriveHistoryTarget,
  getScamHistory,
  HISTORY_CACHE_PREFIX,
  HISTORY_CACHE_TTL_SECONDS,
  normalizeHistoryTarget,
} from './services/scamHistory.js';
import {
  deriveReportDomain,
  deriveReportEndpoint,
  loadReportCounts,
  normalizeReportDomain,
  normalizeReportEndpoint,
  recordEndpointReport,
} from './services/endpointReporting.js';
import {
  connectDatabase,
  disconnectDatabase,
  prisma,
} from './config/prisma.js';
import {
  connectRedis,
  deleteCachedJson,
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
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// -----------------------------------------------------------------------------
// Multer Configuration (Memory Storage for In-Memory Image Ingestion)
// -----------------------------------------------------------------------------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (_req, file, cb) => {
    const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/webp'];
    if (allowedMimeTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('INVALID_FILE_TYPE'));
    }
  },
});

function handleUpload(req, res, next) {
  upload.single('image')(req, res, (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({
          success: false,
          error: 'Image file size exceeds the 5MB limit.',
        });
      }
      if (err.message === 'INVALID_FILE_TYPE') {
        return res.status(400).json({
          success: false,
          error: 'Only image/jpeg, image/png, and image/webp formats are supported.',
        });
      }
      return res.status(400).json({ success: false, error: err.message });
    }
    next();
  });
}

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

async function persistScanReport({
  hash,
  target,
  rawContent,
  inputType,
  verdict,
}) {
  try {
    await prisma.scanReport.upsert({
      where: { contentHash: hash },
      create: {
        contentHash: hash,
        target,
        rawContent,
        inputType,
        riskLevel: verdict.risk_level,
        redFlags: JSON.stringify(verdict.red_flags),
        explanation: verdict.explanation,
        actionableGuidance: JSON.stringify(verdict.actionable_guidance),
      },
      update: {
        target,
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
    version: '2.0.0',
    capabilities: [
      'Layer 1: DPDP Act PII Sanitization',
      'Layer 2: Domain Age & RDAP Checks',
      'Layer 3: Qwen 2.5 + Indian Scam Knowledge Base & Fallback',
      'Multi-modal Image Upload & OCR Ingestion',
      'Redis Caching & SQLite / PostgreSQL Persistence',
    ],
    timestamp: new Date().toISOString(),
  });
});

/**
 * Common threat analysis controller for POST /api/analyze and POST /api/v1/analyze.
 */
async function handleAnalyze(req, res, next) {
  let content = req.body?.content;
  let inputType = req.body?.inputType || 'text';
  let imageMetadata = null;

  // Handle image upload and OCR text ingestion
  if (req.file) {
    inputType = 'image';
    imageMetadata = {
      filename: req.file.originalname,
      mimeType: req.file.mimetype,
      sizeBytes: req.file.size,
    };

    content = req.body?.content || req.body?.ocrText || '';
    if (!content || typeof content !== 'string' || content.trim().length === 0) {
      // Automatically extract text from image buffer using Tesseract OCR
      const ocrResult = await extractTextFromBuffer(req.file.buffer);
      content = ocrResult.text;
      imageMetadata.ocrExtracted = ocrResult.extracted;
    }

    if (!content || typeof content !== 'string' || content.trim().length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Uploaded image contains no readable text. Please ensure the image has clear visible text, or provide text in the description.',
      });
    }
  }

  if (typeof inputType !== 'string' || typeof content !== 'string' || content.trim() === '') {
    return res.status(400).json({
      success: false,
      error: 'Request must include a non-empty string "content" (or an uploaded image).',
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
        const reportEndpoint = deriveReportEndpoint(
          content,
          cachedResponse.metadataChecks,
        );
        const reportDomain = deriveReportDomain(
          reportEndpoint,
          cachedResponse.metadataChecks,
        );
        const reportCounts = await loadReportCounts({
          endpoint: reportEndpoint,
          domain: reportDomain,
        });

        res.set('X-Cache', 'HIT');
        return res.status(200).json({
          ...cachedResponse,
          ...reportCounts,
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

  // Layer 1: preprocessing & DPDP Act compliance PII sanitization
  const layer1 = preprocessInput(inputType, content);

  if (!layer1.success) {
    return res.status(400).json({
      success: false,
      stage: 'layer1_preprocessing',
      error: layer1.error,
      metadata: layer1.metadata,
    });
  }

  // Layer 2: metadata checks (RDAP, domain age, whitelist/blacklist)
  let metadataChecks;
  try {
    metadataChecks = await checkMetadata(layer1.cleanedText);
  } catch (error) {
    console.warn(`[metadata] Layer 2 failed: ${error.message}`);
    metadataChecks = fallbackMetadataError(error);
  }

  // Layer 3: Qwen verdict with Indian scam cross-referencing & deterministic fallback
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

  // Persistence: best-effort database write
  const target = deriveHistoryTarget(metadataChecks, hash);
  const persisted = await persistScanReport({
    hash,
    target,
    rawContent: content,
    inputType: layer1.metadata.inputType,
    verdict,
  });

  if (persisted) {
    await deleteCachedJson(`${HISTORY_CACHE_PREFIX}${target}`);
  }

  const reportEndpoint = deriveReportEndpoint(content, metadataChecks);
  const reportDomain = deriveReportDomain(reportEndpoint, metadataChecks);
  const reportCounts = await loadReportCounts({
    endpoint: reportEndpoint,
    domain: reportDomain,
  });

  const responsePayload = {
    success: true,
    cached: false,
    endpointReportCount: reportCounts.endpointReportCount,
    domainReportCount: reportCounts.domainReportCount,
    input: {
      inputType: layer1.metadata.inputType,
      contentHash: hash,
      target,
    },
    preprocessing: {
      cleanedText: layer1.cleanedText,
      metadata: layer1.metadata,
    },
    dpdpCompliance: layer1.dpdpCompliance,
    imageMetadata: imageMetadata || undefined,
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
}

// Analysis routes (both /api/analyze and /api/v1/analyze for compatibility)
app.post('/api/analyze', handleUpload, handleAnalyze);
app.post('/api/v1/analyze', handleUpload, handleAnalyze);

/**
 * GET /api/dataset/india-scams (and /api/v1/dataset/india-scams)
 * Serves curated Indian scam patterns knowledge base with optional filters.
 */
const datasetHandler = (req, res) => {
  const dataset = getIndiaScamDataset();
  const { jobId, q } = req.query;
  let filtered = dataset;

  if (jobId && typeof jobId === 'string') {
    filtered = filtered.filter(
      (p) => p.jobId?.toLowerCase() === jobId.trim().toLowerCase()
    );
  }

  if (q && typeof q === 'string') {
    const query = q.toLowerCase();
    filtered = filtered.filter(
      (p) =>
        p.title?.toLowerCase().includes(query) ||
        p.financialTrap?.toLowerCase().includes(query) ||
        p.salaryRange?.toLowerCase().includes(query)
    );
  }

  return res.status(200).json({
    success: true,
    count: filtered.length,
    data: filtered,
  });
};

app.get('/api/dataset/india-scams', datasetHandler);
app.get('/api/v1/dataset/india-scams', datasetHandler);

/**
 * POST /api/report (and /api/v1/report)
 * Records an endpoint report and increments endpoint/domain report counts.
 */
const reportHandler = async (req, res) => {
  const { targetEndpoint, inputType, domain } = req.body ?? {};

  const normalizedEndpoint = normalizeReportEndpoint(targetEndpoint);
  if (!normalizedEndpoint) {
    return res.status(400).json({
      success: false,
      error: 'Request body must include a non-empty string "targetEndpoint".',
    });
  }

  if (inputType !== undefined && typeof inputType !== 'string') {
    return res.status(400).json({
      success: false,
      error: '"inputType" must be a string when provided.',
    });
  }

  let normalizedDomain = null;
  if (
    domain !== undefined &&
    domain !== null &&
    String(domain).trim() !== ''
  ) {
    normalizedDomain = normalizeReportDomain(domain);
    if (!normalizedDomain) {
      return res.status(400).json({
        success: false,
        error: '"domain" must be a valid domain name when provided.',
      });
    }
  }

  try {
    const result = await recordEndpointReport({
      targetEndpoint: normalizedEndpoint,
      inputType,
      domain: normalizedDomain,
    });

    const historyKeys = new Set();
    const endpointHistoryTarget = normalizeHistoryTarget(normalizedEndpoint);
    if (endpointHistoryTarget) {
      historyKeys.add(`${HISTORY_CACHE_PREFIX}${endpointHistoryTarget}`);
    }
    if (result.domain) {
      historyKeys.add(`${HISTORY_CACHE_PREFIX}${result.domain}`);
    }
    if (result.report.target) {
      historyKeys.add(`${HISTORY_CACHE_PREFIX}${result.report.target}`);
    }

    await Promise.allSettled(
      [...historyKeys].map((key) => deleteCachedJson(key)),
    );

    return res.status(201).json({
      success: true,
      reportId: result.report.id,
      targetEndpoint: result.report.targetEndpoint,
      domain: result.domain,
      endpointReportCount: result.report.reportCount,
      domainReportCount: result.domainReportCount,
      status: 'RECORDED',
    });
  } catch (error) {
    console.error('[report] could not record endpoint report:', error);
    return res.status(500).json({
      success: false,
      error: 'Could not record the endpoint report.',
    });
  }
};

app.post('/api/report', reportHandler);
app.post('/api/v1/report', reportHandler);

/**
 * GET /api/scam-history?target=<domain_or_hash>
 * Cache-aside date aggregation for a domain, IP, or SHA-256 content hash.
 */
app.get('/api/scam-history', async (req, res) => {
  const { target: rawTarget } = req.query;

  if (typeof rawTarget !== 'string' || rawTarget.trim() === '') {
    return res.status(400).json({
      error: 'Query parameter "target" is required.',
    });
  }

  const target = normalizeHistoryTarget(rawTarget);
  if (!target) {
    return res.status(400).json({
      error: 'Query parameter "target" must be a domain, IP, or content hash.',
    });
  }

  const cacheKey = `${HISTORY_CACHE_PREFIX}${target}`;
  let cacheState = 'MISS';

  try {
    if (!isRedisReady()) {
      cacheState = 'BYPASS';
      logCacheBypass('client is not ready');
    } else {
      const cachedHistory = await getCachedJson(cacheKey);

      if (cachedHistory) {
        res.set('X-Cache', 'HIT');
        return res.status(200).json(cachedHistory);
      }
    }
  } catch (error) {
    cacheState = 'BYPASS';
    logCacheBypass(error?.message || 'cache lookup failed');
  }

  res.set('X-Cache', cacheState);

  try {
    const history = await getScamHistory(target);

    try {
      await setCachedJson(cacheKey, history, HISTORY_CACHE_TTL_SECONDS);
    } catch (error) {
      console.warn(`[cache] could not store ${cacheKey}: ${error.message}`);
    }

    return res.status(200).json(history);
  } catch (error) {
    console.error('[history] query failed:', error);
    return res.status(503).json({
      error: 'Scam history is temporarily unavailable.',
    });
  }
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
