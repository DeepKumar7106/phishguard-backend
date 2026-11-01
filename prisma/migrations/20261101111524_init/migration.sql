-- CreateTable
CREATE TABLE "ScanReport" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "contentHash" TEXT NOT NULL,
    "rawContent" TEXT NOT NULL,
    "inputType" TEXT NOT NULL,
    "riskLevel" TEXT NOT NULL,
    "redFlags" TEXT NOT NULL,
    "explanation" TEXT NOT NULL,
    "actionableGuidance" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateTable
CREATE TABLE "DomainCache" (
    "domain" TEXT NOT NULL PRIMARY KEY,
    "ageInDays" INTEGER,
    "isWhitelisted" BOOLEAN NOT NULL DEFAULT false,
    "isBlacklisted" BOOLEAN NOT NULL DEFAULT false,
    "updatedAt" DATETIME NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "ScanReport_contentHash_key" ON "ScanReport"("contentHash");
