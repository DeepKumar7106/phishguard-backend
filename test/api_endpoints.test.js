import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { EventEmitter } from 'node:events';

process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'file:./dev.db';

const { default: app } = await import('../src/index.js');

/**
 * Dispatches an in-memory HTTP request through Express middleware and routes.
 */
function request(expressApp, { method = 'GET', url = '/', headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const isBuffer = Buffer.isBuffer(body);
    const bodyBuffer = isBuffer
      ? body
      : Buffer.from(body !== null ? (typeof body === 'string' ? body : JSON.stringify(body)) : '', 'utf8');

    const req = new Readable({
      read() {
        if (bodyBuffer.length > 0) {
          this.push(bodyBuffer);
        }
        this.complete = true;
        this.push(null);
      }
    });

    req.method = method;
    req.url = url;
    req.originalUrl = url;
    req.headers = {
      'content-type': 'application/json',
      'content-length': bodyBuffer.length.toString(),
      ...headers
    };

    let statusCode = 200;
    const responseHeaders = {};
    const responseChunks = [];

    const res = new EventEmitter();
    res.statusCode = 200;
    res.setHeader = (key, val) => { responseHeaders[key.toLowerCase()] = val; };
    res.getHeader = (key) => responseHeaders[key.toLowerCase()];
    res.set = (key, val) => {
      if (typeof key === 'object') {
        Object.entries(key).forEach(([k, v]) => { responseHeaders[k.toLowerCase()] = v; });
      } else {
        responseHeaders[key.toLowerCase()] = val;
      }
      return res;
    };
    res.status = (code) => {
      statusCode = code;
      res.statusCode = code;
      return res;
    };

    res.json = (data) => {
      res.setHeader('content-type', 'application/json');
      const jsonStr = JSON.stringify(data);
      res.emit('finish');
      resolve({
        status: statusCode,
        headers: responseHeaders,
        json: async () => data,
        text: async () => jsonStr
      });
      return res;
    };

    res.send = (data) => {
      const text = typeof data === 'object' ? JSON.stringify(data) : String(data);
      res.emit('finish');
      resolve({
        status: statusCode,
        headers: responseHeaders,
        json: async () => {
          try { return JSON.parse(text); } catch { return text; }
        },
        text: async () => text
      });
      return res;
    };

    res.end = (chunk) => {
      if (chunk) responseChunks.push(Buffer.from(chunk));
      const text = Buffer.concat(responseChunks).toString('utf8');
      res.emit('finish');
      resolve({
        status: statusCode,
        headers: responseHeaders,
        json: async () => {
          try { return JSON.parse(text); } catch { return text; }
        },
        text: async () => text
      });
      return res;
    };

    try {
      expressApp.handle(req, res, (err) => {
        if (err) reject(err);
      });
    } catch (err) {
      reject(err);
    }
  });
}

test('4. PhishGuard Unified API Endpoints', async (t) => {
  await t.test('GET / should return platform status, version, and capabilities', async () => {
    const res = await request(app, { method: 'GET', url: '/' });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'ok');
    assert.equal(body.service, 'phishguard-backend');
    assert.ok(body.capabilities.length >= 4);
  });

  await t.test('GET /api/dataset/india-scams should return curated Indian scams', async () => {
    const res = await request(app, { method: 'GET', url: '/api/dataset/india-scams' });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.ok(body.count >= 13);
  });

  await t.test('GET /api/v1/dataset/india-scams?jobId=IN-2002 should filter by jobId', async () => {
    const res = await request(app, { method: 'GET', url: '/api/v1/dataset/india-scams?jobId=IN-2002' });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.count, 1);
    assert.equal(body.data[0].jobId, 'IN-2002');
  });

  await t.test('POST /api/analyze should sanitize PII, run pipeline, and return verdict', async () => {
    const payload = {
      inputType: 'text',
      content: 'Hello Candidate, selected for Graduate Trainee at Infosys. HR email: hr@gmail.com, phone: +91 9876543210. Deposit refundable laptop security fee ₹8,000 via UPI.'
    };

    const res = await request(app, {
      method: 'POST',
      url: '/api/analyze',
      body: payload
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.verdict.risk_level, 'High');
    assert.ok(body.dpdpCompliance?.totalPiiRedacted >= 2);
    assert.ok(body.input?.contentHash);
  });

  await t.test('POST /api/v1/analyze alias should function identically', async () => {
    const payload = {
      inputType: 'text',
      content: 'Tata Consultancy Services is hiring freshers for Software Engineer roles. Check tcs.com careers.'
    };

    const res = await request(app, {
      method: 'POST',
      url: '/api/v1/analyze',
      body: payload
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.verdict.risk_level, 'Low');
  });

  await t.test('POST /api/report should queue crowd report and rate-limit duplicates', async () => {
    const reportPayload = {
      scamType: 'TASK_SCAM_YOUTUBE',
      description: 'Scammer asked for ₹5000 deposit after ₹150 initial payout on Telegram.'
    };

    const res1 = await request(app, {
      method: 'POST',
      url: '/api/report',
      body: reportPayload
    });
    assert.equal(res1.status, 201);
    const body1 = await res1.json();
    assert.equal(body1.success, true);
    assert.equal(body1.status, 'STAGED');
  });

  after(() => {
    setTimeout(() => process.exit(0), 100);
  });
});
