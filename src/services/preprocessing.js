/**
 * Layer 1: Rule Engine - input preprocessing.
 *
 * Responsible for turning raw user input into a clean, standardized value that
 * later layers can safely consume. Layer 2 (metadata checks) and Layer 3
 * (Qwen RAG engine) should only ever see the cleaned text produced here.
 */

// Zero-width, invisible, and bidirectional control characters. These are
// commonly injected to break keyword filters or visually spoof text.
const INVISIBLE_CHARACTERS =
  /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206A\u3164\uFE00-\uFE0F\uFEFF\uFFA0]/g;

// Common Latin-lookalike characters (Cyrillic/Greek/misc) used in homoglyph
// attacks. NFKC handles compatibility forms (fullwidth, math letters, etc.);
// this map covers visually identical letters that NFKC leaves untouched.
const CONFUSABLE_MAP = {
  '\u0430': 'a', // Cyrillic a
  '\u0432': 'b', // Cyrillic ve
  '\u0435': 'e', // Cyrillic ie
  '\u043A': 'k', // Cyrillic ka
  '\u043C': 'm', // Cyrillic em
  '\u043D': 'h', // Cyrillic en
  '\u043E': 'o', // Cyrillic o
  '\u0440': 'p', // Cyrillic er
  '\u0441': 'c', // Cyrillic es
  '\u0442': 't', // Cyrillic te
  '\u0443': 'y', // Cyrillic u
  '\u0445': 'x', // Cyrillic ha
  '\u0455': 's', // Cyrillic dze
  '\u0456': 'i', // Cyrillic byelorussian-ukrainian i
  '\u0458': 'j', // Cyrillic je
  '\u04BB': 'h', // Cyrillic shha
  '\u0501': 'd', // Cyrillic komi de
  '\u051B': 'q', // Cyrillic qa
  '\u03B1': 'a', // Greek alpha
  '\u03BF': 'o', // Greek omicron
  '\u03BD': 'v', // Greek nu
};

/**
 * Remove invisible/zero-width characters and normalize unicode forms.
 *
 * @param {string} value Raw text.
 * @returns {{ text: string, invisibleRemoved: number, homoglyphsNormalized: number }}
 */
function normalizeText(value) {
  const invisibleRemoved = (value.match(INVISIBLE_CHARACTERS) || []).length;

  // NFKC collapses fullwidth and compatibility characters (e.g. "Ａ" -> "A",
  // "𝐚" -> "a") before we look for remaining confusables.
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

  // NFKC can introduce decomposition artifacts, so settle on NFC for the final
  // canonical form, then standardize whitespace and trim.
  const text = deconfused.normalize('NFC').replace(/\s+/g, ' ').trim();

  return { text, invisibleRemoved, homoglyphsNormalized };
}

/**
 * Preprocess raw input for the analysis pipeline.
 *
 * @param {string} inputType One of "text" (extendable later for "url", "email").
 * @param {string} content Raw user-provided content.
 * @returns {{
 *   success: boolean,
 *   cleanedText: string,
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

  switch (normalizedType) {
    case 'text': {
      const { text, invisibleRemoved, homoglyphsNormalized } =
        normalizeText(content);

      return {
        success: true,
        cleanedText: text,
        metadata: {
          inputType: normalizedType,
          originalLength: content.length,
          cleanedLength: text.length,
          invisibleCharactersRemoved: invisibleRemoved,
          homoglyphsNormalized,
          modified: text !== content,
          normalizationForm: 'NFKC->NFC',
        },
      };
    }

    default:
      // Layer 2/3 input types (url, email, screenshot OCR) will be added here.
      return {
        success: false,
        cleanedText: '',
        metadata: { inputType: normalizedType },
        error: `Unsupported inputType: "${normalizedType}".`,
      };
  }
}

export default preprocessInput;
