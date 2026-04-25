import { z } from "zod";

export const moveCallDescriptorSchema = z.object({
  package: z.string().min(3),
  module: z.string().min(1),
  function: z.string().min(1),
});

export const sponsorRequestSchema = z.object({
  transactionKind: z.string().min(8),
  sender: z.string().min(3),
  requestedCalls: z.array(moveCallDescriptorSchema).default([]),
  purchaseAmountMist: z.number().int().positive().optional(),
  recipient: z.string().min(3).max(128).optional(),
  maxGasBudget: z.number().int().positive().optional(),
  network: z.enum(["testnet", "mainnet"]).optional(),
  idempotencyKey: z.string().min(6).max(128).optional(),
});

export const quoteRequestSchema = sponsorRequestSchema;
export const checkoutSessionCreateSchema = z.object({
  appId: z.string().min(1),
  recipient: z.string().min(3).max(128),
  purchaseAmountMist: z.number().int().positive(),
  network: z.enum(["testnet", "mainnet"]).default("testnet"),
  memo: z.string().max(140).optional(),
  merchantReference: z.string().min(1).max(100).optional(),
  expiresInMinutes: z.number().int().min(1).max(1440).default(30),
});

export const checkoutSponsorSchema = sponsorRequestSchema.extend({
  token: z.string().min(12),
});

export type MoveCallDescriptor = z.infer<typeof moveCallDescriptorSchema>;
export type SponsorRequest = z.infer<typeof sponsorRequestSchema>;
export type QuoteRequest = z.infer<typeof quoteRequestSchema>;
export type CheckoutSessionCreate = z.infer<typeof checkoutSessionCreateSchema>;
export type CheckoutSponsorRequest = z.infer<typeof checkoutSponsorSchema>;
