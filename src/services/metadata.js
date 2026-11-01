/**
 * Layer 2: Metadata & Domain Verification.
 *
 * Extracts domains from cleaned text, checks local whitelist/blacklist data and
 * the Prisma DomainCache before making an RDAP request, then classifies domain
 * age into HIGH (<30 days) and MEDIUM (<90 days) risk signals.
 */

import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';

import { prisma } from '../config/prisma.js';

const RDAP_BASE_URL = 'https://rdap.org/domain';
const RDAP_TIMEOUT_MS = 8_000;
const MAX_DOMAINS = 5;
const DOMAIN_CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1_000;
const HIGH_RISK_DAYS = 30;
const MEDIUM_RISK_DAYS = 90;

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3 };

const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.in', 'net.in', 'org.in', 'ac.in', 'edu.in', 'gov.in',
  'co.nz', 'net.nz', 'org.nz',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'com.br', 'net.br', 'org.br',
  'com.mx', 'com.ar', 'com.co', 'com.pe', 'com.cl',
  'com.sg', 'com.hk', 'com.cn', 'com.tw', 'com.tr',
  'co.za', 'co.ke', 'com.ng', 'com.pk', 'com.bd', 'com.lk',
  'co.id', 'com.my', 'com.ph', 'com.vn', 'co.th',
]);

// Avoid treating filenames as domains (e.g. "index.html", "bundle.js").
const FILE_EXTENSIONS = new Set([
  'html', 'htm', 'js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx', 'css', 'json',
  'xml', 'txt', 'md', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp',
  'ico', 'zip', 'rar', '7z', 'exe', 'dll', 'mp3', 'mp4', 'mov', 'avi',
  'csv', 'yml', 'yaml', 'php', 'asp', 'aspx', 'jsp', 'sh', 'bat', 'ps1',
]);

const URL_REGEX = /https?:\/\/[^\s<>"'`]+/gi;
const EMAIL_REGEX = /\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,63})\b/gi;
const DOMAIN_REGEX = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi;

let listsPromise;
let databaseWarningLogged = false;

function warnDatabaseOnce(error) {
  if (databaseWarningLogged) {
    return;
  }
  databaseWarningLogged = true;
  console.warn(
    `[metadata] DomainCache unavailable, continuing without DB cache: ${error.message}`,
  );
}

function normalizeHostname(rawHostname) {
  return String(rawHostname ?? '')
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');
}

function getRegistrableDomain(hostname) {
  const labels = hostname.split('.');
  if (labels.length <= 2) {
    return hostname;
  }

  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_PART_SUFFIXES.has(lastTwo)) {
    return labels.slice(-3).join('.');
  }

  return lastTwo;
}

function normalizeListEntry(entry) {
  if (typeof entry !== 'string') {
    return null;
  }

  let value = entry.trim().toLowerCase();
  if (!value) {
    return null;
  }

  value = value
    .replace(/^https?:\/\//, '')
    .split('/')[0]
    .replace(/^www\./, '')
    .replace(/\.$/, '');

  if (!value || (!value.includes('.') && !isIP(value))) {
    return null;
  }

  return value;
}

async function loadJsonList(fileName) {
  try {
    const fileUrl = new URL(`../data/${fileName}`, import.meta.url);
    const raw = await readFile(fileUrl, 'utf8');
    const parsed = JSON.parse(raw);
    const entries = Array.isArray(parsed) ? parsed : parsed?.domains;

    if (!Array.isArray(entries)) {
      return [];
    }

    return entries.map(normalizeListEntry).filter(Boolean);
  } catch (error) {
    console.warn(`[metadata] could not load ${fileName}: ${error.message}`);
    return [];
  }
}

function loadLists() {
  listsPromise ??= Promise.all([
    loadJsonList('whitelist.json'),
    loadJsonList('blacklist.json'),
  ]).then(([whitelist, blacklist]) => ({
    whitelist: new Set(whitelist),
    blacklist: new Set(blacklist),
  }));

  return listsPromise;
}

function isListed(entries, hostname, domain) {
  if (entries.has(hostname) || entries.has(domain)) {
    return true;
  }

  for (const entry of entries) {
    if (hostname.endsWith(`.${entry}`)) {
      return true;
    }
  }

  return false;
}

/**
 * Extract unique domains and URLs from text. IP literals are included so they
 * can be reported without attempting an RDAP lookup.
 */
export function extractDomains(text) {
  const candidates = new Map();

  const addCandidate = (rawHostname) => {
    const hostname = normalizeHostname(rawHostname);
    if (!hostname || hostname.length > 253) {
      return;
    }

    const ipVersion = isIP(hostname);
    if (!ipVersion) {
      if (!hostname.includes('.')) {
        return;
      }

      const tld = hostname.split('.').pop();
      if (!/^[a-z]{2,63}$/.test(tld) || FILE_EXTENSIONS.has(tld)) {
        return;
      }
      if (!/^[a-z0-9.-]+$/.test(hostname)) {
        return;
      }
    }

    const domain = ipVersion ? hostname : getRegistrableDomain(hostname);
    if (!candidates.has(domain)) {
      candidates.set(domain, {
        hostname,
        domain,
        isIp: Boolean(ipVersion),
      });
    }
  };

  for (const match of String(text ?? '').matchAll(URL_REGEX)) {
    const rawUrl = match[0].replace(/[)\],.;!?]+$/, '');
    try {
      const parsed = new URL(rawUrl);
      addCandidate(parsed.hostname);
    } catch {
      // Ignore malformed URLs; the remaining text is still scanned.
    }
  }

  for (const match of String(text ?? '').matchAll(EMAIL_REGEX)) {
    addCandidate(match[1]);
  }

  for (const match of String(text ?? '').matchAll(DOMAIN_REGEX)) {
    addCandidate(match[0]);
  }

  return [...candidates.values()];
}

async function readDomainCache(domain) {
  try {
    return await prisma.domainCache.findUnique({ where: { domain } });
  } catch (error) {
    warnDatabaseOnce(error);
    return null;
  }
}

async function upsertDomainCache({
  domain,
  ageInDays,
  isWhitelisted,
  isBlacklisted,
}) {
  try {
    await prisma.domainCache.upsert({
      where: { domain },
      create: {
        domain,
        ageInDays,
        isWhitelisted,
        isBlacklisted,
      },
      update: {
        ...(ageInDays !== null && ageInDays !== undefined
          ? { ageInDays }
          : {}),
        isWhitelisted,
        isBlacklisted,
      },
    });
  } catch (error) {
    warnDatabaseOnce(error);
  }
}

function isFreshCacheRecord(record) {
  const updatedAt = new Date(record.updatedAt).getTime();
  return (
    Number.isFinite(updatedAt) &&
    Date.now() - updatedAt < DOMAIN_CACHE_TTL_MS
  );
}

function effectiveCachedAge(record) {
  if (record.ageInDays === null || record.ageInDays === undefined) {
    return null;
  }

  const updatedAt = new Date(record.updatedAt).getTime();
  const elapsedDays = Number.isFinite(updatedAt)
    ? Math.max(0, Math.floor((Date.now() - updatedAt) / 86_400_000))
    : 0;

  return record.ageInDays + elapsedDays;
}

async function lookupRdap(domain) {
  try {
    const response = await fetch(
      `${RDAP_BASE_URL}/${encodeURIComponent(domain)}`,
      {
        headers: {
          Accept: 'application/rdap+json',
          'User-Agent': 'PhishGuard/1.0',
        },
        redirect: 'follow',
        signal: AbortSignal.timeout(RDAP_TIMEOUT_MS),
      },
    );

    if (response.status === 404) {
      return { status: 'not_found' };
    }

    if (!response.ok) {
      return {
        status: 'unavailable',
        error: `RDAP returned HTTP ${response.status}`,
      };
    }

    const data = await response.json();
    const events = Array.isArray(data.events) ? data.events : [];
    const registrationEvent = events.find((event) => {
      const action = String(event.eventAction ?? '').toLowerCase();
      return action === 'registration' || action === 'registered';
    });

    if (!registrationEvent?.eventDate) {
      return { status: 'no_date' };
    }

    const createdAt = new Date(registrationEvent.eventDate);
    if (Number.isNaN(createdAt.getTime())) {
      return { status: 'no_date' };
    }

    return {
      status: 'verified',
      createdDate: createdAt.toISOString(),
      ageInDays: Math.floor((Date.now() - createdAt.getTime()) / 86_400_000),
    };
  } catch (error) {
    return {
      status: 'unavailable',
      error:
        error?.name === 'TimeoutError'
          ? 'RDAP request timed out'
          : error?.message || 'RDAP request failed',
    };
  }
}

function addFlag(flags, domain, code, severity, message) {
  flags.push({ code, severity, message, domain });
}

function riskFromFlags(flags, fallback) {
  let highest = -1;

  for (const flag of flags) {
    highest = Math.max(highest, SEVERITY_RANK[flag.severity] ?? 0);
  }

  if (highest >= SEVERITY_RANK.high) {
    return 'High';
  }
  if (highest >= SEVERITY_RANK.medium) {
    return 'Medium';
  }
  if (highest >= SEVERITY_RANK.low) {
    return 'Low';
  }

  return fallback;
}

async function analyzeDomain(candidate, lists) {
  const { hostname, isIp } = candidate;
  const domain = isIp ? hostname : getRegistrableDomain(hostname);
  const isPunycode = hostname.includes('xn--');
  const flags = [];
  const errors = [];

  let source = 'rdap';
  let isWhitelisted = isListed(lists.whitelist, hostname, domain);
  let isBlacklisted = isListed(lists.blacklist, hostname, domain);
  let ageInDays = null;
  let rdapStatus = null;
  let resolved = false;

  if (isIp) {
    addFlag(
      flags,
      domain,
      'IP_LITERAL_DOMAIN',
      'high',
      `${hostname} is an IP-literal host.`,
    );
    source = 'ip';
    resolved = true;
  } else if (isBlacklisted) {
    addFlag(
      flags,
      domain,
      'BLACKLISTED_DOMAIN',
      'high',
      `${domain} is on the local blacklist.`,
    );
    source = 'blacklist';
    await upsertDomainCache({
      domain,
      ageInDays: null,
      isWhitelisted,
      isBlacklisted,
    });
    resolved = true;
  } else if (isWhitelisted) {
    addFlag(
      flags,
      domain,
      'WHITELISTED_DOMAIN',
      'info',
      `${domain} is on the local whitelist.`,
    );
    source = 'whitelist';
    await upsertDomainCache({
      domain,
      ageInDays: null,
      isWhitelisted: true,
      isBlacklisted: false,
    });
    resolved = true;
  }

  if (!resolved) {
    const cached = await readDomainCache(domain);
    let staleFallbackAge = null;

    if (cached) {
      isWhitelisted = Boolean(cached.isWhitelisted);
      isBlacklisted = Boolean(cached.isBlacklisted);

      if (isBlacklisted) {
        addFlag(
          flags,
          domain,
          'BLACKLISTED_DOMAIN',
          'high',
          `${domain} is marked as blacklisted in the domain cache.`,
        );
        source = 'cache';
        resolved = true;
      } else if (isWhitelisted) {
        addFlag(
          flags,
          domain,
          'WHITELISTED_DOMAIN',
          'info',
          `${domain} is marked as whitelisted in the domain cache.`,
        );
        source = 'cache';
        resolved = true;
      } else if (isFreshCacheRecord(cached)) {
        ageInDays = effectiveCachedAge(cached);
        rdapStatus = ageInDays === null ? 'no_date' : 'verified';
        source = 'cache';
        resolved = true;
      } else if (cached.ageInDays !== null) {
        staleFallbackAge = effectiveCachedAge(cached);
      }
    }

    if (!resolved) {
      const rdap = await lookupRdap(domain);
      rdapStatus = rdap.status;

      if (rdap.status === 'verified') {
        ageInDays = rdap.ageInDays;
        source = 'rdap';
        await upsertDomainCache({
          domain,
          ageInDays,
          isWhitelisted: false,
          isBlacklisted: false,
        });
      } else if (rdap.status === 'not_found') {
        addFlag(
          flags,
          domain,
          'DOMAIN_NOT_FOUND',
          'high',
          `${domain} was not found in RDAP.`,
        );
        source = 'rdap';
      } else if (rdap.status === 'no_date') {
        addFlag(
          flags,
          domain,
          'RDAP_NO_CREATION_DATE',
          'info',
          `RDAP did not provide a registration date for ${domain}.`,
        );
      } else {
        errors.push({
          code: 'RDAP_UNAVAILABLE',
          domain,
          status: rdap.status,
          message: rdap.error || `No RDAP registration date for ${domain}.`,
        });

        if (staleFallbackAge !== null) {
          ageInDays = staleFallbackAge;
          source = 'cache-stale';
        }
      }
    }
  }

  if (ageInDays !== null && !isWhitelisted) {
    if (ageInDays < HIGH_RISK_DAYS) {
      addFlag(
        flags,
        domain,
        'NEWLY_REGISTERED_DOMAIN',
        'high',
        `${domain} was registered ${ageInDays} day(s) ago (under 30 days).`,
      );
    } else if (ageInDays < MEDIUM_RISK_DAYS) {
      addFlag(
        flags,
        domain,
        'RECENTLY_REGISTERED_DOMAIN',
        'medium',
        `${domain} was registered ${ageInDays} day(s) ago (under 90 days).`,
      );
    }
  }

  if (isPunycode && !isWhitelisted) {
    addFlag(
      flags,
      domain,
      'PUNYCODE_DOMAIN',
      'medium',
      `${hostname} uses punycode (xn--), which can hide lookalike characters.`,
    );
  }

  const fallbackRisk =
    ageInDays !== null || source === 'whitelist' ? 'Low' : 'Unknown';

  return {
    hostname,
    domain,
    isIp,
    isPunycode,
    source,
    isWhitelisted,
    isBlacklisted,
    ageInDays,
    rdapStatus,
    riskLevel: riskFromFlags(flags, fallbackRisk),
    flags,
    errors,
  };
}

/**
 * Run Layer 2 metadata checks for cleaned text.
 *
 * Never throws for external-service failures; RDAP and DomainCache errors are
 * reported in `errors` and mark the result as degraded.
 */
export async function checkMetadata(cleanedText) {
  const allCandidates = extractDomains(cleanedText);
  const candidates = allCandidates.slice(0, MAX_DOMAINS);

  if (candidates.length === 0) {
    return {
      success: true,
      skipped: true,
      degraded: false,
      checkedAt: new Date().toISOString(),
      domains: [],
      flags: [],
      errors: [],
      summary: {
        domainCount: 0,
        highRiskDomains: 0,
        mediumRiskDomains: 0,
        truncated: false,
      },
    };
  }

  const lists = await loadLists();
  const domains = [];

  // Sequential lookups keep SQLite writes serialized and avoid RDAP bursts.
  for (const candidate of candidates) {
    domains.push(await analyzeDomain(candidate, lists));
  }

  const flags = domains.flatMap((result) => result.flags);
  const errors = domains.flatMap((result) => result.errors);

  return {
    success: true,
    skipped: false,
    degraded: errors.length > 0,
    checkedAt: new Date().toISOString(),
    domains,
    flags,
    errors,
    summary: {
      domainCount: domains.length,
      highRiskDomains: domains.filter(
        (result) => result.riskLevel === 'High',
      ).length,
      mediumRiskDomains: domains.filter(
        (result) => result.riskLevel === 'Medium',
      ).length,
      truncated: allCandidates.length > candidates.length,
    },
  };
}

export default checkMetadata;
