-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_DomainCache" (
    "domain" TEXT NOT NULL PRIMARY KEY,
    "ageInDays" INTEGER,
    "isWhitelisted" BOOLEAN NOT NULL DEFAULT false,
    "isBlacklisted" BOOLEAN NOT NULL DEFAULT false,
    "reportCount" INTEGER NOT NULL DEFAULT 0,
    "dailyReports" TEXT NOT NULL DEFAULT '[]',
    "updatedAt" DATETIME NOT NULL
);
INSERT INTO "new_DomainCache" ("ageInDays", "dailyReports", "domain", "isBlacklisted", "isWhitelisted", "updatedAt") SELECT "ageInDays", "dailyReports", "domain", "isBlacklisted", "isWhitelisted", "updatedAt" FROM "DomainCache";
DROP TABLE "DomainCache";
ALTER TABLE "new_DomainCache" RENAME TO "DomainCache";
CREATE TABLE "new_ScanReport" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "contentHash" TEXT NOT NULL,
    "target" TEXT,
    "targetEndpoint" TEXT,
    "reportCount" INTEGER NOT NULL DEFAULT 1,
    "domainCacheId" TEXT,
    "rawContent" TEXT NOT NULL,
    "inputType" TEXT NOT NULL,
    "riskLevel" TEXT NOT NULL,
    "redFlags" TEXT NOT NULL,
    "explanation" TEXT NOT NULL,
    "actionableGuidance" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ScanReport_domainCacheId_fkey" FOREIGN KEY ("domainCacheId") REFERENCES "DomainCache" ("domain") ON DELETE SET NULL ON UPDATE CASCADE
);
INSERT INTO "new_ScanReport" ("actionableGuidance", "contentHash", "createdAt", "explanation", "id", "inputType", "rawContent", "redFlags", "riskLevel", "target") SELECT "actionableGuidance", "contentHash", "createdAt", "explanation", "id", "inputType", "rawContent", "redFlags", "riskLevel", "target" FROM "ScanReport";
DROP TABLE "ScanReport";
ALTER TABLE "new_ScanReport" RENAME TO "ScanReport";
CREATE UNIQUE INDEX "ScanReport_contentHash_key" ON "ScanReport"("contentHash");
CREATE UNIQUE INDEX "ScanReport_targetEndpoint_key" ON "ScanReport"("targetEndpoint");
CREATE INDEX "ScanReport_target_createdAt_idx" ON "ScanReport"("target", "createdAt");
CREATE INDEX "ScanReport_domainCacheId_idx" ON "ScanReport"("domainCacheId");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
