/**
 * Endpoint report ingestion and count lookups.
 *
 * A report is keyed by the exact endpoint string (URL, UPI ID, phone number,
 * or handle). Repeated reports increment the existing ScanReport.reportCount
 * and, when a parent domain is supplied, the DomainCache.reportCount.
 */

import { createHash } from 'node:crypto';

import { prisma } from '../config/prisma.js';
import { extractDomains } from './metadata.js';
import { normalizeHistoryTarget } from './scamHistory.js';
import { UPI_DOMAINS } from './preprocessing.js';

const URL_REGEX = /https?:\/\/[^\s<>"'`]+/gi;
const UPI_REGEX = new RegExp(
  `\\b[a-zA-Z0-9.\\-_]{2,40}@(?:${UPI_DOMAINS.join('|')})\\b`,
  'gi',
);
const PHONE_REGEX =
  /(?:(?:\+91|0091|91)[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b/g;
const HANDLE_REGEX = /(?<![\w.])@([A-Za-z0-9_]{3,32})\b/g;
const PHONE_ONLY_PATTERN = /^\+?\d[\d\s()-]{6,}$/;

function stripTrailingPunctuation(value) {
  return value.replace(/[)\],.;!?]+$/, '');
}

export function normalizeReportEndpoint(value) {
  if (typeof value !== 'string') {
    return null;
  }

  const endpoint = stripTrailingPunctuation(value.trim());
  if (!endpoint) {
    return null;
  }

  if (/^https?:\/\//i.test(endpoint)) {
    try {
      const url = new URL(endpoint);
      url.hash = '';
      const normalized = url.toString();

      if (url.pathname === '/' && !url.search) {
        return normalized.replace(/\/$/, '');
      }

      return normalized;
    } catch {
      return endpoint.toLowerCase();
    }
  }

  if (PHONE_ONLY_PATTERN.test(endpoint)) {
    return endpoint.replace(/[^\d+]/g, '');
  }

  return endpoint.toLowerCase();
}

export function normalizeReportDomain(value) {
  if (typeof value !== 'string' || value.trim() === '') {
    return null;
  }

  const [extracted] = extractDomains(value);
  if (extracted && !extracted.isIp) {
    return extracted.domain;
  }

  return null;
}

export function extractReportEndpoints(text) {
  const endpoints = [];
  const seen = new Set();
  const source = String(text ?? '');

  const add = (value) => {
    const normalized = normalizeReportEndpoint(value);
    if (normalized && !seen.has(normalized)) {
      seen.add(normalized);
      endpoints.push(normalized);
    }
  };

  for (const match of source.matchAll(URL_REGEX)) {
    add(stripTrailingPunctuation(match[0]));
  }

  for (const match of source.matchAll(UPI_REGEX)) {
    add(match[0]);
  }

  for (const match of source.matchAll(PHONE_REGEX)) {
    add(match[0]);
  }

  for (const match of source.matchAll(HANDLE_REGEX)) {
    add(`@${match[1]}`);
  }

  if (endpoints.length === 0) {
    const [domain] = extractDomains(source);
    if (domain) {
      add(domain.isIp ? domain.hostname : domain.domain);
    }
  }

  return endpoints;
}

export function deriveReportEndpoint(rawContent, metadataChecks) {
  const [endpoint] = extractReportEndpoints(rawContent);
  if (endpoint) {
    return endpoint;
  }

  const domains = Array.isArray(metadataChecks?.domains)
    ? metadataChecks.domains
    : [];

  return domains.find((domain) => !domain.isIp)?.domain ?? null;
}

export function deriveReportDomain(endpoint, metadataChecks) {
  const domains = Array.isArray(metadataChecks?.domains)
    ? metadataChecks.domains
    : [];
  const fromMetadata = domains.find((domain) => !domain.isIp)?.domain;

  if (fromMetadata) {
    return fromMetadata;
  }

  if (endpoint) {
    const [domain] = extractDomains(endpoint);
    if (domain && !domain.isIp) {
      return domain.domain;
    }
  }

  return null;
}

export async function loadReportCounts({ endpoint, domain }) {
  let endpointReportCount = 0;
  let domainReportCount = 0;

  try {
    const [endpointAggregate, domainCache] = await Promise.all([
      endpoint
        ? prisma.scanReport.aggregate({
            where: { targetEndpoint: endpoint },
            _sum: { reportCount: true },
          })
        : Promise.resolve(null),
      domain
        ? prisma.domainCache.findUnique({
            where: { domain },
            select: { reportCount: true },
          })
        : Promise.resolve(null),
    ]);

    endpointReportCount = endpointAggregate?._sum?.reportCount ?? 0;
    domainReportCount = domainCache?.reportCount ?? 0;
  } catch (error) {
    console.warn(
      `[reporting] could not load report counts: ${error.message}`,
    );
  }

  return { endpointReportCount, domainReportCount };
}

async function ensureDomainCache(domain) {
  try {
    await prisma.domainCache.upsert({
      where: { domain },
      update: {},
      create: { domain },
    });
  } catch {
    // A concurrent report may have created the row at the same time.
  }
}

export async function recordEndpointReport({
  targetEndpoint,
  inputType,
  domain,
}) {
  const normalizedEndpoint = normalizeReportEndpoint(targetEndpoint);
  if (!normalizedEndpoint) {
    throw new Error('A valid targetEndpoint is required.');
  }

  const normalizedDomain = domain ? normalizeReportDomain(domain) : null;
  if (domain && !normalizedDomain) {
    throw new Error('domain must be a valid domain name.');
  }

  const normalizedInputType =
    typeof inputType === 'string' && inputType.trim()
      ? inputType.trim()
      : 'text';

  if (normalizedDomain) {
    await ensureDomainCache(normalizedDomain);
  }

  const contentHash = createHash('sha256')
    .update(`report:${normalizedEndpoint}`, 'utf8')
    .digest('hex');
  const historyTarget =
    normalizedDomain ||
    normalizeHistoryTarget(normalizedEndpoint) ||
    normalizedEndpoint;

  const result = await prisma.$transaction(async (tx) => {
    if (normalizedDomain) {
      await tx.$executeRaw`
        UPDATE "DomainCache"
        SET "reportCount" = "reportCount" + 1
        WHERE "domain" = ${normalizedDomain}
      `;
    }

    const report = await tx.scanReport.upsert({
      where: { targetEndpoint: normalizedEndpoint },
      create: {
        contentHash,
        targetEndpoint: normalizedEndpoint,
        target: historyTarget,
        rawContent: normalizedEndpoint,
        inputType: normalizedInputType,
        riskLevel: 'Unknown',
        redFlags: JSON.stringify(['User-reported threat']),
        explanation: 'Endpoint reported by a user.',
        actionableGuidance: JSON.stringify([]),
        reportCount: 1,
        domainCacheId: normalizedDomain,
      },
      update: {
        reportCount: { increment: 1 },
        target: historyTarget,
        inputType: normalizedInputType,
        ...(normalizedDomain ? { domainCacheId: normalizedDomain } : {}),
      },
    });

    const domainRecord = normalizedDomain
      ? await tx.domainCache.findUnique({
          where: { domain: normalizedDomain },
          select: { reportCount: true },
        })
      : null;

    return { report, domainRecord };
  });

  return {
    report: result.report,
    domain: normalizedDomain,
    domainReportCount: result.domainRecord?.reportCount ?? 0,
  };
}
