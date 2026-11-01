# Project Context: PhishGuard AI Scam Protection Backend

## 1. Executive Summary

PhishGuard is an AI-powered scam protection platform tailored for students. It utilizes a 4-layer hybrid verification pipeline to parse incoming multi-modal suspicious content (text, URLs, screenshots), clean/normalize data, run security checks, and execute model scoring via a local or remote Qwen 2.5 LLM hosted on Ollama.

This repository (`phishguard-backend`) is built on **Node.js (ES Modules) + Express** and handles data ingestion, text preprocessing, domain/metadata checks, Redis caching, SQLite/PostgreSQL persistence, and LLM orchestration.

---

## 2. Architecture Overview & Pipeline Flow

The backend processes incoming requests through a strict 4-Tier verification pipeline:

```
                  [ HTTP POST /api/analyze ]
                             │
                             ▼
     ┌──────────────────────────────────────────────┐
     │  Layer 0: Redis Cache & Payload Hash Check   │
     │  - Compute SHA-256 hash of raw input          │
     │  - Check Redis key `scan:{hash}`             │
     │  - Offline Fallback: If Redis down, set      │
     │    `X-Cache: BYPASS` header and proceed      │
     └───────────────────────┬──────────────────────┘
                             │ (Cache Miss / Bypass)
                             ▼
     ┌──────────────────────────────────────────────┐
     │ Layer 1: Preprocessing & Rule Engine         │
     │  - Strip zero-width spaces (\u200B-\u200D)   │
     │  - Unicode homoglyph normalization           │
     │  - Extract URLs, UPIs, Telegram handles      │
     └───────────────────────┬──────────────────────┘
                             │
                             ▼
     ┌──────────────────────────────────────────────┐
     │ Layer 2: Metadata & Infrastructure Security  │
     │  - Check DB Whitelist / Blacklist            │
     │  - Query RDAP (https://rdap.org/domain/{dom})│
     │  - Compute domain age in days                │
     │  - Flag domains < 30 days as HIGH risk       │
     └───────────────────────┬──────────────────────┘
                             │
                             ▼
     ┌──────────────────────────────────────────────┐
     │ Layer 3: Model Scoring & RAG Core (Qwen 2.5)│
     │  - Query Remote/Local Ollama API             │
     │  - System prompt with metadata context       │
     │  - Strict JSON schema verdict generation     │
     └───────────────────────┬──────────────────────┘
                             │
                             ▼
     ┌──────────────────────────────────────────────┐
     │ Persistence & Caching                        │
     │  - Save ScanReport & DomainCache in Database │
     │  - Cache JSON output in Redis (`SETEX 86400`)│
     └───────────────────────┬──────────────────────┘
                             │
                             ▼
                   [ HTTP 200 OK Response ]
```

---

## 3. Directory Structure

```text
phishguard-backend/
├── package.json
├── .env
├── prisma/
│   └── schema.prisma            # Database schema (SQLite / PostgreSQL)
├── src/
│   ├── index.js                 # Express server & /api/analyze router
│   ├── config/
│   │   ├── prisma.js            # Prisma client instance
│   │   └── redis.js             # ioredis client with offline fallback logic
│   ├── services/
│   │   ├── preprocessing.js     # Layer 1: Text cleaning & normalization
│   │   ├── metadata.js          # Layer 2: RDAP & domain age engine
│   │   └── qwenEngine.js        # Layer 3: Ollama connection & JSON scoring
│   └── utils/
│       └── hash.js              # SHA-256 payload hashing utility
```

---

## 4. Technical Specifications & Environment

### Environment Variables (`.env`)
```env
PORT=5000
DATABASE_URL="file:./dev.db"     # SQLite for local; swap for PostgreSQL in prod
REDIS_URL="redis://localhost:6379"
OLLAMA_HOST="http://10.137.67.51:11434"
OLLAMA_MODEL="qwen2.5:7b"
```

### Prisma Schema (`prisma/schema.prisma`)
*Note: Configured for Node v25 ESM compatibility with Prisma v6.19.3.*

```prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "sqlite" // Change to "postgresql" when deploying to production
  url      = env("DATABASE_URL")
}

model ScanReport {
  id                 String   @id @default(uuid())
  contentHash        String   @unique
  rawContent         String
  inputType          String   @default("text")
  riskLevel          String
  score              Int      @default(0)
  redFlags           String   // Stored as JSON string
  explanation        String
  actionableGuidance String   // Stored as JSON string
  createdAt          DateTime @default(now())
}

model DomainCache {
  domain        String   @id
  ageInDays     Int?
  isWhitelisted Boolean  @default(false)
  isBlacklisted Boolean  @default(false)
  updatedAt     DateTime @updatedAt
}
```

---

## 5. Layer Implementation Details

### Layer 0: Caching & Fallback (`src/config/redis.js`)
* Initializes `ioredis`.
* Wraps commands in `try/catch` to log a warning when Redis is unreachable, allowing server execution with an `X-Cache: BYPASS` header.

### Layer 1: Rule Engine & Preprocessing (`src/services/preprocessing.js`)
* Cleans zero-width characters (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`).
* Applies Unicode NFKD normalization to normalize homoglyphs.
* Extracts domain targets, Telegram (`t.me`), WhatsApp (`wa.me`), and payment patterns.

### Layer 2: Metadata & RDAP Domain Verification (`src/services/metadata.js`)
* Checks Prisma `DomainCache` first.
* Performs an outbound HTTP GET to `https://rdap.org/domain/{domain}` to derive the creation date.
* Calculates domain age in days:
  * $< 30$ Days: High Risk Flag.
  * $< 90$ Days: Medium Risk Flag.

### Layer 3: Model Scoring & Ollama Integration (`src/services/qwenEngine.js`)
* Connects to Ollama (`OLLAMA_HOST`).
* Appends metadata findings (domain age, regex flags) to system prompt.
* Enforces structured JSON output matching schema:
  ```json
  {
    "risk_level": "High | Medium | Low",
    "score": 85,
    "red_flags": ["Upfront fee requested via UPI", "Newly registered domain (12 days old)"],
    "explanation": "Detailed explanation of scam vectors.",
    "actionable_guidance": ["Do not send payments", "Verify company directly"]
  }
  ```

---

## 6. Endpoints Specification

### `POST /api/analyze`
* **Request:**
  ```json
  {
    "inputType": "text",
    "content": "Raw input string or URL to analyze"
  }
  ```
* **Response Headers:** `X-Cache: HIT | MISS | BYPASS`
* **Response Payload (200 OK):**
  ```json
  {
    "status": "success",
    "cached": false,
    "data": {
      "risk_level": "High",
      "score": 90,
      "red_flags": ["Newly registered domain (<15 days)", "Telegram pivot"],
      "explanation": "The domain was registered recently and forces communication to an unmonitored chat app.",
      "actionable_guidance": ["Do not transfer funds", "Avoid joining private Telegram groups"]
    }
  }
  ```

### `GET /api/scam-history?target=<domain>`
* Aggregates scan counts over time from `ScanReport` for chart tracking.

---

## 7. Execution & Migration Commands

```bash
# 1. Install dependencies
npm install

# 2. Run Database Migrations
npx prisma migrate dev --name init
npx prisma generate

# 3. Start Backend Development Server
npm run dev
```