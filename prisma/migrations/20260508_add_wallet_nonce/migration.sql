-- CreateTable WalletNonce
CREATE TABLE "WalletNonce" (
    "id" TEXT NOT NULL,
    "walletAddress" TEXT NOT NULL,
    "nonceHash" TEXT NOT NULL,
    "usedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WalletNonce_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "WalletNonce_nonceHash_key" ON "WalletNonce"("nonceHash");

-- CreateIndex
CREATE INDEX "WalletNonce_walletAddress_expiresAt_idx" ON "WalletNonce"("walletAddress", "expiresAt");

-- CreateIndex
CREATE INDEX "WalletNonce_expiresAt_idx" ON "WalletNonce"("expiresAt");
