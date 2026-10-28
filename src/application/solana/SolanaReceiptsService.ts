import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { err, type Result } from "../../domain/result.js";
import {
  bindSolanaReceipts,
  solanaReceiptsFileSchema,
  solanaReceiptsInputSchema,
} from "../../domain/solana/solanaReceipts.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
import { parseAnalysisInput } from "../AnalysisInput.js";

const OPERATION = "solana_receipts";
const MAX_BYTES = 64 * 1024 * 1024;

export const SOLANA_RECEIPTS_PROVIDER_IDENTITY = {
  id: "solana-receipts",
  name: "REA Solana differential receipt binder",
  version: "1",
} as const;

const invalid = (message: string): AnalysisInputError =>
  new AnalysisInputError(OPERATION, { userMessage: message }, [
    { path: ["receipts_path"], reason: "invalid_value", message },
  ]);

/** Bind local-runner receipts to the analyzed ELF's SHA-256 and emit Evidence. */
export class SolanaReceiptsService {
  readonly identity = SOLANA_RECEIPTS_PROVIDER_IDENTITY;

  close(): Promise<void> {
    return Promise.resolve();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const input = parseAnalysisInput(
      OPERATION,
      rawInput,
      solanaReceiptsInputSchema,
      options?.signal,
    );
    if (!input.ok) return input;
    let elf: Buffer;
    let raw: Buffer;
    try {
      elf = await readFile(input.value.path, { signal: options?.signal });
      raw = await readFile(input.value.receipts_path, {
        signal: options?.signal,
      });
    } catch (cause) {
      return err(
        invalid(`Cannot read selected file: ${(cause as Error).message}`),
      );
    }
    if (elf.length > MAX_BYTES || raw.length > MAX_BYTES)
      return err(invalid("Selected file exceeds the 64 MiB intake allowance."));
    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(raw.toString("utf8"));
    } catch {
      return err(invalid("receipts_path is not valid JSON."));
    }
    const file = solanaReceiptsFileSchema.safeParse(parsedJson);
    if (!file.success)
      return err(
        invalid("receipts_path is not a rea.solana-receipts/v1 document."),
      );
    const sha = (b: Buffer): string =>
      createHash("sha256").update(b).digest("hex");
    const result = bindSolanaReceipts(
      { path: input.value.path, sha256: sha(elf), bytes: elf.length },
      file.data,
      { path: input.value.receipts_path, sha256: sha(raw) },
    );
    return completeProviderEvidence(
      createEvidence(
        {
          path: input.value.path,
          sha256: result.artifact.sha256,
          format: "file",
        },
        this.identity,
        {
          operation: OPERATION,
          parameters: {
            path: input.value.path,
            receipts_path: input.value.receipts_path,
          },
          result,
          confidence: result.binding === "bound" ? "observed" : "inferred",
          limitations: result.limitations,
          locations: [
            { kind: "artifact-path", path: input.value.path },
            { kind: "artifact-path", path: input.value.receipts_path },
          ],
        },
      ),
      options?.signal,
    );
  }
}
