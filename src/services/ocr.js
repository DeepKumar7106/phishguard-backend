/**
 * OCR text extraction service using Tesseract.js.
 * Reads text from in-memory screenshot and image buffers with timeout resilience.
 */
import Tesseract from 'tesseract.js';

/**
 * Extracts text from an image buffer in memory.
 *
 * @param {Buffer} imageBuffer - Raw image file buffer.
 * @param {number} [timeoutMs=8000] - Maximum duration to allow OCR.
 * @returns {Promise<{ text: string, extracted: boolean }>}
 */
export async function extractTextFromBuffer(imageBuffer, timeoutMs = 8000) {
  if (!imageBuffer || !Buffer.isBuffer(imageBuffer)) {
    return { text: '', extracted: false };
  }

  try {
    const ocrPromise = (async () => {
      const { data } = await Tesseract.recognize(imageBuffer, 'eng', {
        logger: () => {}, // silent
      });
      return data?.text ? data.text.trim() : '';
    })();

    const timeoutPromise = new Promise((resolve) =>
      setTimeout(() => resolve(''), timeoutMs)
    );

    const extractedText = await Promise.race([ocrPromise, timeoutPromise]);

    return {
      text: extractedText || '',
      extracted: Boolean(extractedText && extractedText.length > 0),
    };
  } catch (err) {
    console.warn('[ocr] OCR extraction error:', err.message);
    return { text: '', extracted: false };
  }
}

export default { extractTextFromBuffer };
