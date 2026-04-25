import { createHash, randomBytes } from "node:crypto";

import express, { type NextFunction, type Request, type Response } from "express";

import { config } from "./config.js";
import { getPrismaClient } from "./db.js";
import { ApiError } from "./errors.js";
import { SuiGasStationService } from "./sui.js";
import { assertPortalAuthConfigured, verifyPortalToken } from "./portal-auth.js";
import {
  checkoutSessionCreateSchema,
  checkoutSponsorSchema,
} from "./types.js";
import { recordSponsorshipEvent } from "./usage-events.js";

declare global {
  namespace Express {
    interface Request {
      portalUserId?: string;
      portalUserEmail?: string;
    }
  }
}

type CheckoutSessionStatus = "ACTIVE" | "COMPLETED" | "EXPIRED" | "CANCELLED";

const service = new SuiGasStationService();

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function createCheckoutToken(): string {
  return `os_chk_${randomBytes(24).toString("base64url")}`;
}

function getCheckoutToken(req: Request): string | undefined {
  const headerToken = req.header("x-checkout-token")?.trim();
  const bodyToken = typeof req.body?.token === "string" ? req.body.token.trim() : undefined;
  const queryToken = typeof req.query.token === "string" ? req.query.token.trim() : undefined;
  return headerToken || bodyToken || queryToken;
}

function routeParam(req: Request, key: string): string {
  const value = req.params[key];
  return Array.isArray(value) ? value[0] : value;
}

function getCheckoutBaseUrl(req: Request): string {
  const requestOrigin = req.header("origin")?.trim();
  if (requestOrigin) {
    return requestOrigin.replace(/\/$/, "");
  }

  if (config.frontendUrl) {
    return config.frontendUrl.replace(/\/$/, "");
  }

  if (config.nodeEnv !== "production") {
    return "http://localhost:3000";
  }

  return "";
}

function requirePortalAuth(req: Request, _res: Response, next: NextFunction) {
  try {
    assertPortalAuthConfigured();
    const authHeader = req.header("authorization");
    if (!authHeader || !authHeader.toLowerCase().startsWith("bearer ")) {
      throw new ApiError(401, "UNAUTHORIZED", "Missing Bearer token");
    }

    const token = authHeader.slice(7).trim();
    const claims = verifyPortalToken(token);
    req.portalUserId = claims.sub;
    req.portalUserEmail = claims.email;
    return next();
  } catch (error) {
    return next(error);
  }
}

async function loadSession(sessionId: string) {
  const prisma = getPrismaClient();
  if (!prisma) {
    throw new ApiError(503, "PORTAL_DISABLED", "Database is not configured");
  }

  const session = await prisma.checkoutSession.findUnique({
    where: { id: sessionId },
    include: {
      dapp: {
        select: {
          id: true,
          name: true,
          network: true,
          ownerId: true,
        },
      },
    },
  });

  if (!session) {
    throw new ApiError(404, "NOT_FOUND", "Checkout session not found");
  }

  return { prisma, session };
}

async function ensureSessionIsActive(sessionId: string, token?: string) {
  const { prisma, session } = await loadSession(sessionId);

  if (!token || hashToken(token) !== session.tokenHash) {
    throw new ApiError(401, "UNAUTHORIZED", "Invalid checkout token");
  }

  if (session.status !== "ACTIVE") {
    throw new ApiError(409, "CHECKOUT_SESSION_INACTIVE", "Checkout session is not active");
  }

  if (session.expiresAt.getTime() < Date.now()) {
    await prisma.checkoutSession.update({
      where: { id: session.id },
      data: { status: "EXPIRED" },
    });
    throw new ApiError(410, "CHECKOUT_SESSION_EXPIRED", "Checkout session expired");
  }

  return { prisma, session };
}

async function ensureSessionReadable(sessionId: string, token?: string) {
  const { prisma, session } = await loadSession(sessionId);

  if (!token || hashToken(token) !== session.tokenHash) {
    throw new ApiError(401, "UNAUTHORIZED", "Invalid checkout token");
  }

  if (session.status === "ACTIVE" && session.expiresAt.getTime() < Date.now()) {
    await prisma.checkoutSession.update({
      where: { id: session.id },
      data: { status: "EXPIRED" },
    });
    throw new ApiError(410, "CHECKOUT_SESSION_EXPIRED", "Checkout session expired");
  }

  return { prisma, session };
}

export const checkoutRouter = express.Router();

checkoutRouter.post(
  "/portal/checkout/sessions",
  requirePortalAuth,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const prisma = getPrismaClient();
      if (!prisma) {
        throw new ApiError(503, "PORTAL_DISABLED", "Database is not configured");
      }

    const payload = checkoutSessionCreateSchema.parse(req.body);
    const dapp = await prisma.dapp.findFirst({
      where: {
        id: payload.appId,
        ownerId: req.portalUserId as string,
      },
    });

    if (!dapp) {
      throw new ApiError(404, "NOT_FOUND", "App not found");
    }

    const checkoutToken = createCheckoutToken();
    const expiresAt = new Date(Date.now() + payload.expiresInMinutes * 60_000);

    const session = await prisma.checkoutSession.create({
      data: {
        dappId: dapp.id,
        merchantReference: payload.merchantReference,
        recipient: payload.recipient,
        purchaseAmountMist: payload.purchaseAmountMist,
        network: payload.network,
        memo: payload.memo,
        tokenHash: hashToken(checkoutToken),
        expiresAt,
      },
      select: {
        id: true,
        status: true,
        recipient: true,
        purchaseAmountMist: true,
        network: true,
        memo: true,
        merchantReference: true,
        expiresAt: true,
        createdAt: true,
      },
    });

    res.status(201).json({
      ok: true,
      session,
      checkoutToken,
      checkoutUrl: `${getCheckoutBaseUrl(req)}/?checkoutSessionId=${session.id}&checkoutToken=${checkoutToken}`,
    });
    } catch (error) {
      next(error);
    }
  },
);

checkoutRouter.get(
  "/checkout/sessions/:sessionId",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const token = getCheckoutToken(req);
      const { session } = await ensureSessionReadable(routeParam(req, "sessionId"), token);

    res.json({
      ok: true,
      session: {
        id: session.id,
        status: session.status,
        recipient: session.recipient,
        purchaseAmountMist: session.purchaseAmountMist,
        network: session.network,
        memo: session.memo,
        merchantReference: session.merchantReference,
        expiresAt: session.expiresAt,
        createdAt: session.createdAt,
        dapp: {
          id: session.dapp.id,
          name: session.dapp.name,
          network: session.dapp.network,
        },
      },
    });
    } catch (error) {
      next(error);
    }
  },
);

checkoutRouter.post(
  "/checkout/sessions/:sessionId/sponsor",
  async (req: Request, res: Response, next: NextFunction) => {
    const startedAt = Date.now();

    try {
      const token = getCheckoutToken(req);
      const { prisma, session } = await ensureSessionIsActive(routeParam(req, "sessionId"), token);
      const payload = checkoutSponsorSchema.parse(req.body);

    const sponsored = await service.sponsor(
      {
        transactionKind: payload.transactionKind,
        sender: payload.sender,
        requestedCalls: payload.requestedCalls,
        purchaseAmountMist: session.purchaseAmountMist,
        recipient: session.recipient,
        maxGasBudget: payload.maxGasBudget,
        network: session.network as "testnet" | "mainnet",
        idempotencyKey: payload.idempotencyKey,
      },
      session.dapp.name,
    );

    await prisma.checkoutSession.update({
      where: { id: session.id },
      data: { status: "COMPLETED", completedAt: new Date() },
    });

    await recordSponsorshipEvent({
      dappName: session.dapp.name,
      endpoint: `/v1/checkout/sessions/${session.id}/sponsor`,
      status: "success",
      gasBudget: (sponsored as { gasData?: { budget?: number | string } }).gasData?.budget != null
        ? Number((sponsored as { gasData?: { budget?: number | string } }).gasData?.budget)
        : undefined,
      purchaseAmountMist: session.purchaseAmountMist,
      recipient: session.recipient,
      latencyMs: Date.now() - startedAt,
    });

    res.json({
      ok: true,
      session: {
        id: session.id,
        status: "COMPLETED" as CheckoutSessionStatus,
      },
      ...sponsored,
      paymentIntent: {
        merchantReference: session.merchantReference,
        recipient: session.recipient,
        purchaseAmountMist: session.purchaseAmountMist,
        memo: session.memo,
      },
    });
    } catch (error) {
      try {
        const token = getCheckoutToken(req);
        if (token) {
          const sessionId = routeParam(req, "sessionId");
          const { session } = await ensureSessionIsActive(sessionId, token);
          await recordSponsorshipEvent({
            dappName: session.dapp.name,
            endpoint: `/v1/checkout/sessions/${session.id}/sponsor`,
            status: "failed",
            errorCode: error instanceof ApiError ? error.code : "CHECKOUT_SPONSOR_FAILED",
            latencyMs: Date.now() - startedAt,
          });
        }
      } catch {
        // Keep the original error as the response.
      }

      next(error);
    }
  },
);