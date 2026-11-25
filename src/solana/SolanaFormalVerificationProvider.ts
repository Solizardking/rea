import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import type { ExecutionOptions } from "../ports/AnalysisProvider.js";
import type { SolanaFormalVerificationPort } from "../ports/solana/SolanaFormalVerificationPort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisInputError,
  cancelledBy,
  isAborted,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { sha256Hex } from "../kernel/sha256Hex.js";
import { err, ok, type Result } from "../domain/result.js";
import { solanaProgramAnalysisSchema } from "../domain/solana/solanaProgram.js";
import {
  FORMAL_ENGINES,
  type FormalEngine,
  type FormalEngineReport,
  type SolanaFormalVerificationInput,
  type SolanaFormalVerificationResult,
} from "../domain/solana/solanaFormalVerification.js";
import { SOLANA_PROGRAM_PROVIDER_IDENTITY } from "./SolanaProviderIdentity.js";
import {
  FORMAL_ENGINE_ADAPTERS,
  FORMAL_NOT_CLAIMED,
  FormalReportShapeError,
  sumCounts,
} from "./SolanaFormalVerification.js";

const OPERATION = "solana_formal_verification";
const REPORT_FILE = "formal-verification.json";
/** Engine reports and analyses are JSON well under this allowance. */
const MAX_REPORT_BYTES = 64 * 1024 * 1024;

const invalid = (field: string, message: string): AnalysisInputError =>
  new AnalysisInputError(OPERATION, undefined, [
    { path: [field], reason: "invalid_value", message },
  ]);

interface ReadDocument {
  readonly value: unknown;
  readonly sha256: string;
}

/** Read one caller-selected JSON report; every failure names its field. */
const readDocument = async (
  path: string,
  field: string,
  signal: AbortSignal | undefined,
): Promise<Result<ReadDocument, AnalysisError>> => {
  let bytes: Buffer;
  try {
    bytes = await readFile(path, { signal });
  } catch (cause) {
    if (isAborted(signal)) return err(cancelledBy(OPERATION, signal));
    const code = (cause as NodeJS.ErrnoException).code ?? "EIO";
    return err(
      invalid(field, `Selected report cannot be read: ${path} (${code}).`),
    );
  }
  if (bytes.byteLength > MAX_REPORT_BYTES)
    return err(
      invalid(
        field,
        `Selected report ${path} exceeds the ${String(MAX_REPORT_BYTES)}-byte intake allowance.`,
      ),
    );
  try {
    return ok({
      value: JSON.parse(bytes.toString("utf8")) as unknown,
      sha256: sha256Hex(bytes),
    });
  } catch {
    return err(invalid(field, `Selected report is not valid JSON: ${path}.`));
  }
};

type Artifact = SolanaFormalVerificationResult["artifact"];

/**
 * Bind the reports to an artifact: the analysis SHA-256 when an analysis is
 * selected (refusing a different declared SHA-256), else the declared one.
 */
const bindArtifact = async (
  input: SolanaFormalVerificationInput,
  signal: AbortSignal | undefined,
): Promise<Result<{ artifact: Artifact; issues: string[] }, AnalysisError>> => {
  const issues: string[] = [];
  let artifact: Artifact = {
    elf_sha256: input.verified_artifact_sha256 ?? null,
    program_id: null,
    analysis_path: null,
    binding:
      input.verified_artifact_sha256 === undefined ? "unbound" : "declared",
  };
  if (input.analysis_path !== undefined) {
    const read = await readDocument(
      input.analysis_path,
      "analysis_path",
      signal,
    );
    if (!read.ok) return err(read.error);
    const analysis = solanaProgramAnalysisSchema.safeParse(read.value.value);
    if (!analysis.success)
      return err(
        invalid(
          "analysis_path",
          `File is not a solana program analysis: ${input.analysis_path}.`,
        ),
      );
    const sha = analysis.data.artifact.sha256;
    if (
      input.verified_artifact_sha256 !== undefined &&
      input.verified_artifact_sha256 !== sha
    )
      return err(
        invalid(
          "verified_artifact_sha256",
          `Prover runs are declared against artifact ${input.verified_artifact_sha256}, but the analysis covers ${sha}; refusing to bind verdicts across artifacts.`,
        ),
      );
    artifact = {
      elf_sha256: sha,
      program_id: analysis.data.artifact.program_id,
      analysis_path: input.analysis_path,
      binding: "analysis",
    };
    if (input.verified_artifact_sha256 === undefined)
      issues.push(
        "No verified_artifact_sha256 was declared: the verdicts are attached to the analyzed artifact on the caller's word that the prover ran against it.",
      );
  } else if (input.verified_artifact_sha256 === undefined)
    issues.push(
      "No analysis_path or verified_artifact_sha256: verdicts are not bound to any artifact.",
    );

  return ok({ artifact, issues });
};

const ENGINE_FIELDS: Readonly<
  Record<FormalEngine, "certora_verdicts_path" | "aristotle_properties_path">
> = {
  certora: "certora_verdicts_path",
  aristotle: "aristotle_properties_path",
};

/**
 * Normalize Certora Prover and Harmonic Aristotle verdict reports into one
 * REA record, bound by SHA-256 to the Solana artifact they verify. It never
 * submits a prover run and never reads an engine credential's value: only
 * whether the engine CLI's credential variable is present is reported.
 */
export class SolanaFormalVerificationProvider implements SolanaFormalVerificationPort {
  readonly identity = SOLANA_PROGRAM_PROVIDER_IDENTITY;

  constructor(
    private readonly environment: Readonly<NodeJS.ProcessEnv> = process.env,
  ) {}

  async normalize(
    input: SolanaFormalVerificationInput,
    options?: ExecutionOptions,
  ): Promise<Result<SolanaFormalVerificationResult, AnalysisError>> {
    const signal = options?.signal;
    const bound = await bindArtifact(input, signal);
    if (!bound.ok) return bound;
    const { artifact, issues } = bound.value;

    const engines: FormalEngineReport[] = [];
    for (const engine of FORMAL_ENGINES) {
      const field = ENGINE_FIELDS[engine];
      const path = input[field];
      if (path === undefined) continue;
      const read = await readDocument(path, field, signal);
      if (!read.ok) return read;
      try {
        engines.push(
          FORMAL_ENGINE_ADAPTERS[engine].parse(read.value.value, {
            path,
            sha256: read.value.sha256,
          }),
        );
      } catch (cause) {
        if (cause instanceof FormalReportShapeError)
          return err(invalid(field, cause.message));
        throw cause;
      }
    }
    if (isAborted(signal)) return err(cancelledBy(OPERATION, signal));

    const tagged = (verdicts: readonly string[]) =>
      engines.flatMap((report) =>
        report.results
          .filter((result) => verdicts.includes(result.verdict))
          .map((result) => `${report.engine}:${result.name}`),
      );
    const reportPath =
      input.out_path ??
      join(dirname(input.analysis_path as string), REPORT_FILE);
    const body = {
      artifact,
      engines,
      totals: sumCounts(engines.map((report) => report.counts)),
      formally_verified: tagged(["verified"]),
      findings: tagged(["violated", "sanity-failed"]),
      issues: [...issues, ...engines.flatMap((report) => report.issues)],
      not_claimed: [...FORMAL_NOT_CLAIMED],
      readiness: FORMAL_ENGINES.map((engine) => {
        const adapter = FORMAL_ENGINE_ADAPTERS[engine];
        const value = this.environment[adapter.credentialVariable];
        return {
          engine,
          credential_variable: adapter.credentialVariable,
          credential_present: value !== undefined && value.length > 0,
          run_commands: [...adapter.runCommands],
        };
      }),
    };
    const bytes = `${JSON.stringify(body, null, 2)}\n`;
    try {
      await mkdir(dirname(reportPath), { recursive: true });
      // Exclusive create: an earlier report is evidence and is never overwritten.
      await writeFile(reportPath, bytes, { flag: "wx", signal });
    } catch (cause) {
      if (isAborted(signal)) return err(cancelledBy(OPERATION, signal));
      if ((cause as NodeJS.ErrnoException).code === "EEXIST")
        return err(
          invalid(
            "out_path",
            `A report already exists at ${reportPath}; choose a new out_path.`,
          ),
        );
      return err(
        new ProviderAdapterError(
          SOLANA_PROGRAM_PROVIDER_IDENTITY.id,
          OPERATION,
          {
            cause,
          },
        ),
      );
    }
    return ok({
      report_path: reportPath,
      report_sha256: sha256Hex(bytes),
      ...body,
    });
  }
}
