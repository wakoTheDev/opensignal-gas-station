import bcrypt from "bcryptjs";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { SuiJsonRpcClient } from "@mysten/sui/jsonRpc";
import { verifyPersonalMessageSignature } from "@mysten/sui/verify";

import { config } from "./config.js";
import { ApiError } from "./errors.js";

export interface PortalClaims {
  sub: string;
  email: string;
}

const DEFAULT_TOKEN_TTL = "7d";

function defaultRpcUrl(network: string): string {
  return network === "mainnet"
    ? "https://fullnode.mainnet.sui.io:443"
    : "https://fullnode.testnet.sui.io:443";
}

// Shared SuiJsonRpcClient used for zkLogin signature verification.
// zkLogin proofs require fetching the provider JWK from the chain,
// so verifyPersonalMessageSignature must receive a live client.
const suiClient = new SuiJsonRpcClient({
  network: config.network as "testnet" | "mainnet",
  url: config.rpcUrl || defaultRpcUrl(config.network),
});

export function assertPortalAuthConfigured() {
  if (!config.databaseUrl) {
    throw new ApiError(503, "PORTAL_DISABLED", "Set DATABASE_URL (or DIRECT_URL) to enable developer portal features");
  }

  if (!config.portalJwtSecret) {
    throw new ApiError(503, "PORTAL_DISABLED", "Set PORTAL_JWT_SECRET to enable developer portal features");
  }
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export function issuePortalToken(claims: PortalClaims): string {
  if (!config.portalJwtSecret) {
    throw new ApiError(500, "PORTAL_AUTH_MISCONFIGURED", "Portal JWT secret is not configured");
  }

  return jwt.sign(claims, config.portalJwtSecret, { expiresIn: DEFAULT_TOKEN_TTL });
}

export function verifyPortalToken(token: string): PortalClaims {
  if (!config.portalJwtSecret) {
    throw new ApiError(500, "PORTAL_AUTH_MISCONFIGURED", "Portal JWT secret is not configured");
  }

  try {
    const payload = jwt.verify(token, config.portalJwtSecret);
    if (typeof payload !== "object" || payload === null || !("sub" in payload) || !("email" in payload)) {
      throw new ApiError(401, "UNAUTHORIZED", "Invalid auth token");
    }

    return {
      sub: String(payload.sub),
      email: String(payload.email),
    };
  } catch {
    throw new ApiError(401, "UNAUTHORIZED", "Invalid or expired auth token");
  }
}

export function generateApiKey(): string {
  return `os_live_${crypto.randomBytes(24).toString("base64url")}`;
}

export function apiKeyPrefix(apiKey: string): string {
  return apiKey.slice(0, 12);
}

export function hashApiKey(apiKey: string): string {
  return crypto.createHash("sha256").update(apiKey).digest("hex");
}

export async function verifyWalletSignature(
  message: string,
  signature: string,
  walletAddress: string,
): Promise<boolean> {
  try {
    if (!message || !signature || !walletAddress) {
      console.warn("[wallet-auth] Missing required field — message, signature, or walletAddress is empty");
      return false;
    }

    const normalizedAddress = walletAddress.toLowerCase();

    if (!/^0x[a-fA-F0-9]{64}$/.test(normalizedAddress)) {
      console.warn("[wallet-auth] Wallet address failed format check:", normalizedAddress);
      return false;
    }

    const messageBytes = new TextEncoder().encode(message);

    // Pass the SuiJsonRpcClient so that zkLogin signatures can be verified.
    // For standard Ed25519/Secp256k1 signatures the client is ignored.
    // For zkLogin (Google/Apple OAuth wallets like Slush) it is required
    // to fetch the provider JWK from the chain and verify the ZK proof.
    const publicKey = await verifyPersonalMessageSignature(messageBytes, signature, {
      client: suiClient,
    });

    const recoveredAddress = publicKey.toSuiAddress().toLowerCase();
    const match = recoveredAddress === normalizedAddress;

    if (!match) {
      console.warn("[wallet-auth] Address mismatch after signature recovery", {
        recovered: recoveredAddress,
        expected: normalizedAddress,
      });
    }

    return match;
  } catch (error) {
    console.error("[wallet-auth] verifyPersonalMessageSignature threw:", error);
    return false;
  }
}
