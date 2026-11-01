/**
 * Shared Prisma client.
 *
 * A single client is reused across the process and, in development, across
 * nodemon reloads via globalThis. Database failures are handled by callers as
 * best-effort persistence rather than crashing the API.
 */

import { PrismaClient } from '@prisma/client';

const globalForPrisma = globalThis;

export const prisma =
  globalForPrisma.__phishguardPrisma ??
  new PrismaClient({
    log: ['warn', 'error'],
  });

if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.__phishguardPrisma = prisma;
}

export async function connectDatabase() {
  try {
    await prisma.$connect();
    return true;
  } catch (error) {
    console.warn(
      `[database] unavailable, persistence disabled: ${error.message}`,
    );
    return false;
  }
}

export async function disconnectDatabase() {
  try {
    await prisma.$disconnect();
  } catch {
    // Nothing useful to do during shutdown.
  }
}

export default prisma;
