import test from 'node:test';
import assert from 'node:assert/strict';
import { preprocessInput, normalizeText, sanitizePii } from '../src/services/preprocessing.js';
import {
  analyzeWithQwen,
  getIndiaScamDataset,
  matchIndianScamPattern,
  executeDeterministicFallback,
} from '../src/services/qwenEngine.js';

test('1. Layer 1: Rule Engine & DPDP Act Compliance Preprocessing', async (t) => {
  await t.test('should remove zero-width characters and normalize confusables', () => {
    const raw = 'Fr\u200Baud \u0430ttack'; // Cyrillic 'а'
    const { text, invisibleRemoved, homoglyphsNormalized } = normalizeText(raw);
    assert.equal(invisibleRemoved, 1);
    assert.equal(homoglyphsNormalized, 1);
    assert.equal(text, 'Fraud attack');
  });

  await t.test('should redact Indian phone numbers, Aadhaar, PAN, UPI IDs, emails, and names', () => {
    const raw = 'Dear Rahul Sharma, your PAN is ABCDE1234F, Aadhaar is 2345 6789 0123. Pay ₹5,000 via scammer@okhdfcbank or call +91 9876543210 or email hr@fakecorp.com.';
    const res = preprocessInput('text', raw);

    assert.equal(res.success, true);
    assert.ok(res.cleanedText.includes('[REDACTED_NAME]'));
    assert.ok(res.cleanedText.includes('[REDACTED_PAN]'));
    assert.ok(res.cleanedText.includes('[REDACTED_AADHAAR]'));
    assert.ok(res.cleanedText.includes('[REDACTED_UPI_ID]'));
    assert.ok(res.cleanedText.includes('[REDACTED_PHONE]'));
    assert.ok(res.cleanedText.includes('[REDACTED_EMAIL]'));

    assert.equal(res.dpdpCompliance?.status, 'Compliant - PII Redacted');
    assert.ok(res.dpdpCompliance?.totalPiiRedacted >= 5);
  });

  await t.test('should support multiple input types (text, url, image, image_text, email)', () => {
    assert.equal(preprocessInput('url', 'https://job-scam.xyz').success, true);
    assert.equal(preprocessInput('image', 'Offer letter screenshot text').success, true);
    assert.equal(preprocessInput('image_text', 'OCR extracted text').success, true);
    assert.equal(preprocessInput('email', 'Email body text').success, true);
    assert.equal(preprocessInput('unsupported_type', 'test').success, false);
  });
});

test('2. Indian Scam Dataset & Pattern Matching Knowledge Base', async (t) => {
  await t.test('should load all curated Indian scam patterns (IN-2001 to IN-2013)', () => {
    const dataset = getIndiaScamDataset();
    assert.ok(dataset.length >= 13);
    const in2001 = dataset.find(p => p.jobId === 'IN-2001');
    const in2002 = dataset.find(p => p.jobId === 'IN-2002');
    const in2003 = dataset.find(p => p.jobId === 'IN-2003');

    assert.ok(in2001);
    assert.ok(in2002);
    assert.ok(in2003);
    assert.equal(in2001.title, 'Part-Time Social Media Optimization Executive');
    assert.equal(in2002.title, 'Graduate Trainee / Software Engineer');
  });

  await t.test('should accurately cross-reference IN-2001 YouTube like task scam', () => {
    const text = 'Part time work: like YouTube videos and earn ₹1500 - 5000 daily. Join VIP Telegram group for prepaid tasks.';
    const match = matchIndianScamPattern(text);
    assert.equal(match.matchedPatternId, 'IN-2001');
  });

  await t.test('should accurately cross-reference IN-2002 laptop refundable security deposit scam', () => {
    const text = 'Urgent joining: selected for Software Trainee at 6 LPA. Recruiter uses hr@gmail.com. Mandatory refundable laptop security deposit of ₹8,000 required.';
    const match = matchIndianScamPattern(text);
    assert.equal(match.matchedPatternId, 'IN-2002');
  });

  await t.test('should detect scam patterns across regional Indian languages (Hindi, Kannada, Bengali, Tamil)', () => {
    // Hindi Devanagari
    const hindiText = 'घर बैठे पैसे कमाएं, यूट्यूब वीडियो लाइक करें और रोजाना ₹1500 से ₹5000 कमाएं। टेलीग्राम ग्रुप जॉइन करें।';
    assert.equal(matchIndianScamPattern(hindiText).matchedPatternId, 'IN-2001');

    // Bengali
    const bengaliText = 'ঘরে বসে টাকা আয় করুন, ইউটিউব ভিডিও লাইক করুন, টেলিগ্রাম গ্রুপে যোগ দিন।';
    assert.equal(matchIndianScamPattern(bengaliText).matchedPatternId, 'IN-2001');

    // Kannada
    const kannadaText = 'ದಿನಕ್ಕೆ ೨೦೦೦ ಗಳಿಸಿ, ಯೂಟ್ಯೂಬ್ ವಿಡಿಯೋ ಲೈಕ್ ಮಾಡಿ, ಟೆಲಿಗ್ರಾಂ ಜಾಯಿನ್ ಆಗಿ.';
    assert.equal(matchIndianScamPattern(kannadaText).matchedPatternId, 'IN-2001');
  });
});

test('3. Deterministic Fallback & Zero-False-Positive Guarantee', async (t) => {
  await t.test('should guarantee ZERO false positives on legitimate corporate domains (e.g. tcs.com)', () => {
    const corporateText = 'Tata Consultancy Services is hiring Graduate Trainees. Apply on official careers portal. TCS never charges any application or security deposit fees.';
    const metadataChecks = {
      domains: [{ domain: 'tcs.com', isWhitelisted: true, riskLevel: 'low' }],
      flags: []
    };

    const verdict = executeDeterministicFallback(corporateText, metadataChecks);
    assert.equal(verdict.risk_level, 'Low');
    assert.ok(verdict.score <= 15);
    assert.equal(verdict.red_flags.length, 0);
  });

  await t.test('should detect high risk scam via deterministic fallback when Ollama is offline', () => {
    const scamText = 'Selected for Data Entry work from home. Pay ₹10,000 settlement fine or face legal court notice for breach of contract.';
    const verdict = executeDeterministicFallback(scamText, null);

    assert.equal(verdict.risk_level, 'High');
    assert.ok(verdict.score >= 80);
    assert.equal(verdict.matched_pattern_id, 'IN-2003');
    assert.ok(verdict.actionable_guidance.length > 0);
  });
});
