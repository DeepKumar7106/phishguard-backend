-- AlterTable
ALTER TABLE "ScanReport" ADD COLUMN "target" TEXT;

-- Backfill existing reports so they remain addressable by content hash.
UPDATE "ScanReport" SET "target" = "contentHash" WHERE "target" IS NULL;

-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_DomainCache" (
    "domain" TEXT NOT NULL PRIMARY KEY,
    "ageInDays" INTEGER,
    "isWhitelisted" BOOLEAN NOT NULL DEFAULT false,
    "isBlacklisted" BOOLEAN NOT NULL DEFAULT false,
    "dailyReports" TEXT NOT NULL DEFAULT '[]',
    "updatedAt" DATETIME NOT NULL
);
INSERT INTO "new_DomainCache" ("ageInDays", "domain", "isBlacklisted", "isWhitelisted", "updatedAt") SELECT "ageInDays", "domain", "isBlacklisted", "isWhitelisted", "updatedAt" FROM "DomainCache";
DROP TABLE "DomainCache";
ALTER TABLE "new_DomainCache" RENAME TO "DomainCache";
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;

-- CreateIndex
CREATE INDEX "ScanReport_target_createdAt_idx" ON "ScanReport"("target", "createdAt");
