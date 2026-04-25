-- CreateEnum
CREATE TYPE "public"."CheckoutSessionStatus" AS ENUM ('ACTIVE', 'COMPLETED', 'EXPIRED', 'CANCELLED');

-- CreateTable
CREATE TABLE "public"."CheckoutSession" (
    "id" TEXT NOT NULL,
    "dappId" TEXT NOT NULL,
    "merchantReference" TEXT,
    "recipient" TEXT NOT NULL,
    "purchaseAmountMist" INTEGER NOT NULL,
    "network" TEXT NOT NULL DEFAULT 'testnet',
    "memo" TEXT,
    "tokenHash" TEXT NOT NULL,
    "status" "public"."CheckoutSessionStatus" NOT NULL DEFAULT 'ACTIVE',
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CheckoutSession_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "CheckoutSession_tokenHash_key" ON "public"."CheckoutSession"("tokenHash");
CREATE INDEX "CheckoutSession_dappId_status_idx" ON "public"."CheckoutSession"("dappId", "status");
CREATE INDEX "CheckoutSession_expiresAt_idx" ON "public"."CheckoutSession"("expiresAt");

-- AddForeignKey
ALTER TABLE "public"."CheckoutSession" ADD CONSTRAINT "CheckoutSession_dappId_fkey" FOREIGN KEY ("dappId") REFERENCES "public"."Dapp"("id") ON DELETE CASCADE ON UPDATE CASCADE;
