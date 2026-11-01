import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';

import { preprocessInput } from './services/preprocessing.js';
import { analyzeWithQwen, QwenEngineError } from './services/qwenEngine.js';

dotenv.config();

const app = express();

// Global middleware
app.use(cors());
app.use(express.json({ limit: '1mb' }));

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
 * Pipeline: Layer 1 preprocessing -> Layer 3 Qwen verdict.
 * Layer 2 (metadata checks) remains a placeholder for now.
 */
app.post('/api/analyze', async (req, res, next) => {
  const { inputType, content } = req.body ?? {};

  if (!inputType || content === undefined) {
    return res.status(400).json({
      success: false,
      error: 'Request body must include "inputType" and "content".',
    });
  }

  const layer1 = preprocessInput(inputType, content);

  if (!layer1.success) {
    return res.status(400).json({
      success: false,
      stage: 'layer1_preprocessing',
      error: layer1.error,
      metadata: layer1.metadata,
    });
  }

  try {
    const verdict = await analyzeWithQwen(layer1.cleanedText);

    return res.status(200).json({
      success: true,
      input: {
        inputType: layer1.metadata.inputType,
      },
      preprocessing: {
        cleanedText: layer1.cleanedText,
        metadata: layer1.metadata,
      },
      metadataChecks: null,
      verdict,
      layers: {
        layer1: 'completed',
        layer2: 'not_implemented',
        layer3: 'completed',
      },
    });
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

app.listen(PORT, () => {
  console.log(`Server is successfully running on http://localhost:${PORT}`);
});

export default app;
