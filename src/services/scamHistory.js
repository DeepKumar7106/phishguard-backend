/**
 * Historical scam-report aggregation.
 *
 * ScanReport rows are aggregated in UTC by calendar day. The materialized
 * dailyReports field on DomainCache is kept in sync for consumers that need
 * the latest aggregate without querying ScanReport.
 */

import { prisma } from '../config/prisma.js';
import { extractDomains } from './metadata.js';

export const HISTORY_CACHE_PREFIX = 'scam:history:';
export const HISTORY_CACHE_TTL_SECONDS = 300;

const CONTENT_HASH_PATTERN = /^[a-f0-9]{64}$/i;

/**
 * Normalize an API target into a domain, IP, or content hash.
 *
 * Accepts bare domains, URLs, emails, and 64-character SHA-256 hashes.
 */
export function normalizeHistoryTarget(rawTarget) {
  if (typeof rawTarget !== 'string') {
    return null;
  }

  const trimmed = rawTarget.trim();
  if (!trimmed) {
    return null;
  }

  if (CONTENT_HASH_PATTERN.test(trimmed)) {
    return trimmed.toLowerCase();
  }

  const [extracted] = extractDomains(trimmed);
  if (extracted) {
    return extracted.isIp ? extracted.hostname : extracted.domain;
  }

  return (
    trimmed
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .split(/[/?#]/)[0]
      .replace(/^www\./, '')
      .replace(/\.$/, '') || null
  );
}

/**
 * Choose the target stored on a ScanReport. Prefer the primary non-IP domain;
 * fall back to the content hash when no domain is present.
 */
export function deriveHistoryTarget(metadataChecks, contentHash) {
  const domains = Array.isArray(metadataChecks?.domains)
    ? metadataChecks.domains
    : [];
  const primaryDomain =
    domains.find((domain) => !domain.isIp) ?? domains[0];

  return primaryDomain?.domain || contentHash;
}

function dateKey(createdAt) {
  const date =
    createdAt instanceof Date ? createdAt : new Date(createdAt);

  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date.toISOString().slice(0, 10);
}

/**
 * Aggregate report timestamps into [{ date: 'YYYY-MM-DD', count }] sorted by
 * date ascending.
 */
export function aggregateReportsByDate(reports) {
  const counts = new Map();

  for (const report of reports ?? []) {
    const date = dateKey(report?.createdAt);
    if (!date) {
      continue;
    }

    const reportCount = Number.isFinite(report?.reportCount)
      ? Math.max(0, report.reportCount)
      : 1;

    counts.set(date, (counts.get(date) ?? 0) + reportCount);
  }

  return [...counts.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([date, count]) => ({ date, count }));
}

async function syncDomainDailyReports(target, timeSeries) {
  if (CONTENT_HASH_PATTERN.test(target)) {
    return;
  }

  const [domain] = extractDomains(target);
  if (!domain || domain.isIp || timeSeries.length === 0) {
    return;
  }

  const serialized = JSON.stringify(timeSeries);

  try {
    const updated = await prisma.$executeRaw`
      UPDATE "DomainCache"
      SET "dailyReports" = ${serialized}
      WHERE "domain" = ${domain.domain}
    `;

    if (updated > 0) {
      return;
    }

    await prisma.domainCache.create({
      data: {
        domain: domain.domain,
        dailyReports: serialized,
      },
    });
  } catch {
    try {
      await prisma.$executeRaw`
        UPDATE "DomainCache"
        SET "dailyReports" = ${serialized}
        WHERE "domain" = ${domain.domain}
      `;
    } catch (retryError) {
      console.warn(
        `[history] could not refresh DomainCache for ${domain.domain}: ${retryError.message}`,
      );
    }
  }
}

/**
 * Load and aggregate scam history for a domain, IP, or content hash.
 *
 * @param {string} rawTarget Domain, URL, IP, or SHA-256 content hash.
 * @returns {Promise<{target: string, totalReports: number, timeSeries: Array<{date: string, count: number}>}>}
 */
export async function getScamHistory(rawTarget) {
  const target = normalizeHistoryTarget(rawTarget);

  if (!target) {
    throw new Error('A valid target is required.');
  }

  const reports = await prisma.scanReport.findMany({
    where: {
      OR: [{ target }, { contentHash: target }],
    },
    select: { createdAt: true, reportCount: true },
    orderBy: { createdAt: 'asc' },
  });

  const timeSeries = aggregateReportsByDate(reports);
  const totalReports = timeSeries.reduce(
    (sum, point) => sum + point.count,
    0,
  );

  await syncDomainDailyReports(target, timeSeries);

  return {
    target,
    totalReports,
    timeSeries,
  };
}

export default getScamHistory;
