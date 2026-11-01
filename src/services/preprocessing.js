/**
 * Layer 1: Rule Engine - input preprocessing & DPDP Act (2023) PII Sanitization.
 *
 * Turns raw user input into a clean, standardized, DPDP-compliant value that
 * downstream layers (Layer 2 metadata checks & Layer 3 Qwen RAG engine) can safely consume.
 * Strips zero-width characters, homoglyphs, and redacts sensitive PII (Indian phone numbers,
 * Aadhaar, PAN, UPI IDs, bank accounts, emails, and candidate names).
 */

// Zero-width, invisible, and bidirectional control characters.
const INVISIBLE_CHARACTERS =
  /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206A\u3164\uFE00-\uFE0F\uFEFF\uFFA0]/g;

// Common Latin-lookalike characters (Cyrillic/Greek/misc) used in homoglyph attacks.
const CONFUSABLE_MAP = {
  '\u0430': 'a', '\u0432': 'b', '\u0435': 'e', '\u043A': 'k',
  '\u043C': 'm', '\u043D': 'h', '\u043E': 'o', '\u0440': 'p',
  '\u0441': 'c', '\u0442': 't', '\u0443': 'y', '\u0445': 'x',
  '\u0455': 's', '\u0456': 'i', '\u0458': 'j', '\u04BB': 'h',
  '\u0501': 'd', '\u051B': 'q', '\u03B1': 'a', '\u03BF': 'o',
  '\u03BD': 'v',
};

const UPI_DOMAINS = [
  'okaxis', 'okhdfcbank', 'oksbi', 'okicici', 'paytm', 'ybl', 'ibl', 'axl',
  'apl', 'barodampay', 'upi', 'idfcbank', 'federal', 'indus', 'kotak'
];

/**
 * Remove invisible/zero-width characters and normalize unicode forms.
 *
 * @param {string} value Raw text.
 * @returns {{ text: string, invisibleRemoved: number, homoglyphsNormalized: number }}
 */
export function normalizeText(value) {
  if (!value || typeof value !== 'string') {
    return { text: '', invisibleRemoved: 0, homoglyphsNormalized: 0 };
  }

  const invisibleRemoved = (value.match(INVISIBLE_CHARACTERS) || []).length;
  const withoutInvisible = value.replace(INVISIBLE_CHARACTERS, '');
  const compatibilityNormalized = withoutInvisible.normalize('NFKC');

  let homoglyphsNormalized = 0;
  const deconfused = compatibilityNormalized.replace(
    /[\u0430\u0432\u0435\u043A\u043C\u043D\u043E\u0440\u0441\u0442\u0443\u0445\u0455\u0456\u0458\u04BB\u0501\u051B\u03B1\u03BF\u03BD]/g,
    (char) => {
      homoglyphsNormalized += 1;
      return CONFUSABLE_MAP[char] ?? char;
    },
  );

  const text = deconfused
    .normalize('NFC')
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/\r\n/g, '\n')
    .replace(/[ \t]+/g, ' ')
    .replace(/[ \t]*\n[ \t]*/g, '\n')
    .replace(/\n\s*\n\s*\n+/g, '\n\n')
    .trim();

  return { text, invisibleRemoved, homoglyphsNormalized };
}

/**
 * DPDP Act PII Sanitization: strips personal and financial identifiers.
 *
 * @param {string} text - Normalized text.
 * @returns {{ sanitizedText: string, piiSummary: object, redactedTypes: string[] }}
 */
export function sanitizePii(text) {
  if (!text || typeof text !== 'string') {
    return {
      sanitizedText: '',
      piiSummary: { totalRedacted: 0 },
      redactedTypes: []
    };
  }

  let sanitized = text;
  const counts = {
    phoneNumbersCount: 0,
    emailsCount: 0,
    upiIdsCount: 0,
    aadhaarCount: 0,
    panCount: 0,
    namesCount: 0,
    bankAccountsCount: 0
  };

  // 1. Aadhaar (12 digits)
  const aadhaarRegex = /\b[2-9]{1}\d{3}[\s-]?\d{4}[\s-]?\d{4}\b/g;
  sanitized = sanitized.replace(aadhaarRegex, (match) => {
    const digitsOnly = match.replace(/[\s-]/g, '');
    if (digitsOnly.length === 12) {
      counts.aadhaarCount++;
      return '[REDACTED_AADHAAR]';
    }
    return match;
  });

  // 2. PAN Card (5 letters, 4 digits, 1 letter)
  const panRegex = /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g;
  sanitized = sanitized.replace(panRegex, () => {
    counts.panCount++;
    return '[REDACTED_PAN]';
  });

  // 3. Bank Account / Card Numbers
  const cardRegex = /\b(?:\d{4}[ -]?){3}\d{4}\b/g;
  sanitized = sanitized.replace(cardRegex, () => {
    counts.bankAccountsCount++;
    return '[REDACTED_CARD_NUMBER]';
  });

  const bankAccountRegex = /\b(?:A\/C|Account|Acc|Acct)[\s#.:-]*(\d{9,18})\b/gi;
  sanitized = sanitized.replace(bankAccountRegex, (match, accNum) => {
    counts.bankAccountsCount++;
    return match.replace(accNum, '[REDACTED_BANK_ACCOUNT]');
  });

  // 4. UPI IDs
  const upiPatternStr = `\\b[a-zA-Z0-9.\\-_]{2,40}@(${UPI_DOMAINS.join('|')})\\b`;
  const upiRegex = new RegExp(upiPatternStr, 'gi');
  sanitized = sanitized.replace(upiRegex, () => {
    counts.upiIdsCount++;
    return '[REDACTED_UPI_ID]';
  });

  // 5. Email Addresses
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  sanitized = sanitized.replace(emailRegex, () => {
    counts.emailsCount++;
    return '[REDACTED_EMAIL]';
  });

  // 6. Indian and International Phone Numbers
  const indianPhoneRegex = /(?:(?:\+91|0091|91)[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b/g;
  sanitized = sanitized.replace(indianPhoneRegex, () => {
    counts.phoneNumbersCount++;
    return '[REDACTED_PHONE]';
  });

  // 7. Salutation Names
  const nameSalutationRegex = /\b(Dear|Hello|Hi|Greetings|Contact|HR|Mr\.|Ms\.|Mrs\.)\s+([A-Z][a-z]{2,15}(?:\s+[A-Z][a-z]{2,15})?)\b/g;
  sanitized = sanitized.replace(nameSalutationRegex, (match, prefix) => {
    counts.namesCount++;
    return `${prefix} [REDACTED_NAME]`;
  });

  const totalRedacted = Object.values(counts).reduce((acc, curr) => acc + curr, 0);

  const redactedTypes = [];
  if (counts.phoneNumbersCount > 0) redactedTypes.push('Phone Number');
  if (counts.emailsCount > 0) redactedTypes.push('Email Address');
  if (counts.upiIdsCount > 0) redactedTypes.push('UPI ID');
  if (counts.aadhaarCount > 0) redactedTypes.push('Aadhaar Number');
  if (counts.panCount > 0) redactedTypes.push('PAN Card');
  if (counts.namesCount > 0) redactedTypes.push('Personal Name');
  if (counts.bankAccountsCount > 0) redactedTypes.push('Financial Detail');

  return {
    sanitizedText: sanitized,
    piiSummary: { ...counts, totalRedacted },
    redactedTypes
  };
}

const SUPPORTED_INPUT_TYPES = new Set(['text', 'url', 'image', 'image_text', 'email']);

/**
 * Preprocess raw input for the analysis pipeline with DPDP Act compliance.
 *
 * @param {string} inputType One of "text", "url", "image", "image_text", "email".
 * @param {string} content Raw user-provided content.
 * @returns {{
 *   success: boolean,
 *   cleanedText: string,
 *   rawNormalizedText?: string,
 *   dpdpCompliance?: object,
 *   metadata: object,
 *   error?: string
 * }}
 */
export function preprocessInput(inputType, content) {
  if (typeof inputType !== 'string' || inputType.trim() === '') {
    return {
      success: false,
      cleanedText: '',
      metadata: {},
      error: 'inputType is required.',
    };
  }

  if (typeof content !== 'string' || content.trim() === '') {
    return {
      success: false,
      cleanedText: '',
      metadata: {},
      error: 'content must be a non-empty string.',
    };
  }

  const normalizedType = inputType.trim().toLowerCase();

  if (!SUPPORTED_INPUT_TYPES.has(normalizedType)) {
    return {
      success: false,
      cleanedText: '',
      metadata: { inputType: normalizedType },
      error: `Unsupported inputType: "${normalizedType}". Supported types: ${[...SUPPORTED_INPUT_TYPES].join(', ')}`,
    };
  }

  // 1. Normalize characters and zero-width confusables
  const { text: normalizedText, invisibleRemoved, homoglyphsNormalized } = normalizeText(content);

  // 2. DPDP Act (2023) PII Sanitization
  const { sanitizedText, piiSummary, redactedTypes } = sanitizePii(normalizedText);

  return {
    success: true,
    cleanedText: sanitizedText,
    rawNormalizedText: normalizedText,
    dpdpCompliance: {
      status: piiSummary.totalRedacted > 0 ? 'Compliant - PII Redacted' : 'Compliant - No PII Detected',
      totalPiiRedacted: piiSummary.totalRedacted,
      redactedTypes,
    },
    metadata: {
      inputType: normalizedType,
      originalLength: content.length,
      cleanedLength: sanitizedText.length,
      invisibleCharactersRemoved: invisibleRemoved,
      homoglyphsNormalized,
      piiRedacted: piiSummary.totalRedacted,
      modified: sanitizedText !== content,
      normalizationForm: 'NFKC->NFC+DPDP',
    },
  };
}

export default preprocessInput;
