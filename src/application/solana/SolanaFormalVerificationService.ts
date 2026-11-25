import type { ExecutionOptions } from "../../ports/AnalysisProvider.js";
import type { SolanaFormalVerificationPort } from "../../ports/solana/SolanaFormalVerificationPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisOutputError } from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  solanaFormalVerificationInputSchema,
  solanaFormalVerificationResultSchema,
} from "../../domain/solana/solanaFormalVerification.js";
import { err, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
import { parseAnalysisInput } from "../AnalysisInput.js";

const OPERATION = "solana_formal_verification";

const LIMITATIONS: readonly string[] = [
  "Verdicts are read from caller-supplied Certora prover-cli and Harmonic Aristotle report files; this tool never submits a prover run.",
  "A verified result holds only under the engine's documented assumptions; the report's not_claimed list states what no verdict here establishes.",
];

/** Shared exact input validation and report-bound Evidence for CLI and MCP. */
export class SolanaFormalVerificationService {
  constructor(readonly provider: SolanaFormalVerificationPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  /**
   * Normalize engine reports into one formal-verification record. Labeled
   * inferred: the verdicts are the engines' claims, carried and bound to an
   * artifact here, not observations this tool made.
   */
  async normalize(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const input = parseAnalysisInput(
      OPERATION,
      rawInput,
      solanaFormalVerificationInputSchema,
      options?.signal,
    );
    if (!input.ok) return input;
    const built = await this.provider.normalize(input.value, options);
    if (!built.ok) return built;
    const report = solanaFormalVerificationResultSchema.safeParse(built.value);
    if (!report.success)
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Solana formal-verification normalizer returned malformed data.",
        ),
      );
    const value = report.data;
    const { out_path: _outPath, ...parameters } = input.value;
    return completeProviderEvidence(
      createEvidence(
        {
          path: value.report_path,
          sha256: value.report_sha256,
          format: "file",
        },
        this.provider.identity,
        {
          operation: OPERATION,
          parameters: { ...parameters, report_path: value.report_path },
          result: value,
          confidence: "inferred",
          limitations: [...LIMITATIONS],
          locations: [
            { kind: "artifact-path", path: value.report_path },
            ...value.engines.map(
              (engine) =>
                ({ kind: "artifact-path", path: engine.source_path }) as const,
            ),
          ],
        },
      ),
      options?.signal,
    );
  }
}
