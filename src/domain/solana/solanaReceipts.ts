import { z } from "zod";

import { absoluteLocalPathStringSchema } from "../localPath.js";
import { solanaPublicKeySchema } from "./solanaProgram.js";

const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/);

/** Local execution engines whose receipts REA accepts as differential evidence. */
export const SUPPORTED_RECEIPT_ENGINES = [
  "litesvm",
  "solana-test-validator",
  "surfpool",
  "mollusk",
] as const;

/** Select the analyzed ELF and a receipts file produced by a local runner. */
export const solanaReceiptsInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema.describe(
    "Absolute path to the sBPF ELF the receipts claim to have executed",
  ),
  receipts_path: absoluteLocalPathStringSchema.describe(
    "Absolute path to a rea.solana-receipts/v1 JSON file",
  ),
});

/** One runner observation: a transaction against the loaded ELF and its predicate. */
export const solanaReceiptSchema = z.object({
  tag: z.int().min(0).max(255),
  instruction: z.string().min(1),
  kind: z.enum(["positive", "negative"]),
  expectation: z.string(),
  pass: z.boolean(),
  tx_ok: z.boolean(),
  err: z.string().nullable(),
  compute_units: z.int().nonnegative(),
  log_instruction: z.string().nullable().optional(),
});

/** File produced by a local receipts runner (never a live cluster). */
export const solanaReceiptsFileSchema = z.object({
  schema: z.literal("rea.solana-receipts/v1"),
  engine: z.object({
    name: z.string(),
    version: z.string(),
    network: z.string(),
  }),
  program_id: solanaPublicKeySchema,
  artifact_sha256: sha256Schema,
  receipts: z.array(solanaReceiptSchema),
});

export const solanaReceiptClaimSchema = z.strictObject({
  tag: z.int().min(0).max(255),
  instruction: z.string(),
  status: z.enum(["receipt-verified", "lead"]),
  reason: z.string(),
  positive_passed: z.int().nonnegative(),
  negative_passed: z.int().nonnegative(),
  failed: z.int().nonnegative(),
});

export const solanaReceiptsResultSchema = z.strictObject({
  artifact: z.strictObject({
    path: z.string(),
    sha256: sha256Schema,
    bytes: z.int().nonnegative(),
  }),
  receipts_file: z.strictObject({
    path: z.string(),
    sha256: sha256Schema,
    engine: z.string(),
    engine_version: z.string(),
    network: z.string(),
    program_id: z.string(),
  }),
  binding: z.enum([
    "bound",
    "artifact-mismatch",
    "unsupported-engine",
    "networked-engine",
  ]),
  claims: z.array(solanaReceiptClaimSchema),
  counts: z.strictObject({
    receipt_verified: z.int().nonnegative(),
    lead: z.int().nonnegative(),
    receipts: z.int().nonnegative(),
  }),
  limitations: z.array(z.string()),
});

export type SolanaReceiptsInput = z.infer<typeof solanaReceiptsInputSchema>;
export type SolanaReceiptsFile = z.infer<typeof solanaReceiptsFileSchema>;
export type SolanaReceiptsResult = z.infer<typeof solanaReceiptsResultSchema>;
type Binding = SolanaReceiptsResult["binding"];

/**
 * Bind runner receipts to the analyzed artifact. A claim is promoted to
 * `receipt-verified` only when the file's artifact hash equals the ELF's,
 * the engine is a supported local runtime with no network, and the tag has
 * at least one passing positive receipt and no failing receipt. Everything
 * else is downgraded to `lead` with the reason recorded.
 */
export const bindSolanaReceipts = (
  artifact: SolanaReceiptsResult["artifact"],
  file: SolanaReceiptsFile,
  receiptsFile: { path: string; sha256: string },
): SolanaReceiptsResult => {
  const binding: Binding =
    file.artifact_sha256 !== artifact.sha256
      ? "artifact-mismatch"
      : !(SUPPORTED_RECEIPT_ENGINES as readonly string[]).includes(
            file.engine.name,
          )
        ? "unsupported-engine"
        : file.engine.network !== "none"
          ? "networked-engine"
          : "bound";
  const byTag = new Map<number, (typeof file.receipts)[number][]>();
  for (const receipt of file.receipts)
    byTag.set(receipt.tag, [...(byTag.get(receipt.tag) ?? []), receipt]);
  const claims = [...byTag.entries()]
    .sort(([a], [b]) => a - b)
    .map(([tag, receipts]) => {
      const positive = receipts.filter(
        (r) => r.kind === "positive" && r.pass && r.tx_ok,
      ).length;
      const negative = receipts.filter(
        (r) => r.kind === "negative" && r.pass,
      ).length;
      const failed = receipts.filter((r) => !r.pass).length;
      const instruction =
        (receipts.find((r) => r.kind === "positive") ?? receipts[0])
          ?.instruction ?? "";
      let reason: string;
      if (binding === "artifact-mismatch")
        reason = `receipts were produced against ${file.artifact_sha256}, not this artifact`;
      else if (binding === "unsupported-engine")
        reason = `engine ${file.engine.name} is not a supported local runtime`;
      else if (binding === "networked-engine")
        reason = `engine network is "${file.engine.network}", not "none"`;
      else if (failed > 0)
        reason = `${String(failed)} receipt(s) failed their expectation`;
      else if (positive === 0)
        reason = "negative controls only; no positive behavior observed";
      else
        reason = `${String(positive)} positive receipt(s) passed on the bound artifact`;
      const verified = binding === "bound" && failed === 0 && positive > 0;
      return {
        tag,
        instruction,
        status: verified ? ("receipt-verified" as const) : ("lead" as const),
        reason,
        positive_passed: positive,
        negative_passed: negative,
        failed,
      };
    });
  const verifiedCount = claims.filter(
    (c) => c.status === "receipt-verified",
  ).length;
  return {
    artifact,
    receipts_file: {
      path: receiptsFile.path,
      sha256: receiptsFile.sha256,
      engine: file.engine.name,
      engine_version: file.engine.version,
      network: file.engine.network,
      program_id: file.program_id,
    },
    binding,
    claims,
    counts: {
      receipt_verified: verifiedCount,
      lead: claims.length - verifiedCount,
      receipts: file.receipts.length,
    },
    limitations: [
      "REA verifies receipt binding and predicates as recorded by the runner; it does not re-execute transactions.",
      "A receipt shows behavior on the tested inputs only; it is not a proof of equivalence for all inputs.",
    ],
  };
};
