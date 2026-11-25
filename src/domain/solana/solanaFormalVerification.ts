import { z } from "zod";

import { digestSchema } from "../digests.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";

const count = z.int().nonnegative();

/**
 * Normalized verdicts across formal-verification engines. Only `verified`
 * is a proof, and only under the engine's documented assumptions; every
 * other value is either a finding (`violated`, `sanity-failed`) or no
 * verdict at all.
 */
export const FORMAL_VERDICTS = [
  "verified",
  "violated",
  "sanity-failed",
  "timeout",
  "error",
  "in-progress",
  "unresolved",
  "unchecked",
  "unknown",
] as const;

export const formalVerdictSchema = z.enum(FORMAL_VERDICTS);
export type FormalVerdict = z.infer<typeof formalVerdictSchema>;

export const FORMAL_ENGINES = ["certora", "aristotle"] as const;
export const formalEngineSchema = z.enum(FORMAL_ENGINES);
export type FormalEngine = z.infer<typeof formalEngineSchema>;

/**
 * Certora `prover-cli --job-id <id> --verdicts --format json` output
 * (Certora/ProverCLI `JobVerdicts.to_dict`): leaf-check status counts per
 * rule. Unknown members are tolerated so newer prover-cli releases still
 * parse; only the fields read here are typed.
 */
export const certoraVerdictsSchema = z.looseObject({
  job_id: z.string().min(1).max(256),
  job_status: z.string().min(1).max(64),
  rules: z.record(
    z.string().min(1).max(512),
    z.looseObject({
      counts: z.record(z.string().min(1).max(64), count),
      leaves: z
        .array(
          z.looseObject({
            method: z.string().nullable().optional(),
            status: z.string().min(1).max(64),
            assert: z.string().nullable().optional(),
          }),
        )
        .max(65_536)
        .optional(),
    }),
  ),
});

/**
 * Harmonic Aristotle `aristotle properties <project-id> --json` output
 * (aristotlelib `DeclarationPage` of `DeclarationRecord`). Status names
 * come from the computed `status_name` field; `unchecked` marks a proof or
 * refutation Aristotle never checked.
 */
export const aristotlePropertiesSchema = z.looseObject({
  project_id: z.string().min(1).max(256),
  declarations: z
    .array(
      z.looseObject({
        declaration_id: z.string().min(1).max(256).optional(),
        declaration_type_name: z.string().max(64).optional(),
        name: z.string().min(1).max(512),
        status_name: z.string().min(1).max(64),
        failure_reason_name: z.string().max(64).nullable().optional(),
        evidence_message: z.string().nullable().optional(),
        description: z.string().nullable().optional(),
        source_file: z.string().nullable().optional(),
        source_line: z.int().nullable().optional(),
        unchecked: z.boolean().optional(),
      }),
    )
    .max(65_536),
});

export type AristotleProperties = z.infer<typeof aristotlePropertiesSchema>;

/**
 * Select engine reports to normalize and, optionally, the REA Solana
 * analysis whose artifact SHA-256 the reports are bound to. Reports are
 * caller-produced files; this tool never submits a prover run.
 */
export const solanaFormalVerificationInputSchema = z
  .strictObject({
    analysis_path: absoluteLocalPathStringSchema
      .optional()
      .describe(
        "Absolute path to the solana-analysis.json of the program the reports verify",
      ),
    verified_artifact_sha256: digestSchema
      .optional()
      .describe(
        "SHA-256 of the sBPF artifact the prover runs were made against (e.g. the prebuilt .so passed to certoraSolanaProver); must match the analysis when both are given",
      ),
    certora_verdicts_path: absoluteLocalPathStringSchema
      .optional()
      .describe(
        "Absolute path to `prover-cli --job-id <id> --verdicts --format json` output",
      ),
    aristotle_properties_path: absoluteLocalPathStringSchema
      .optional()
      .describe(
        "Absolute path to `aristotle properties <project-id> --json` output",
      ),
    out_path: absoluteLocalPathStringSchema
      .optional()
      .describe(
        "Absolute path for the new formal-verification.json report; defaults beside analysis_path; never overwritten",
      ),
  })
  .superRefine((value, context) => {
    if (
      value.certora_verdicts_path === undefined &&
      value.aristotle_properties_path === undefined
    )
      context.addIssue({
        code: "custom",
        path: ["certora_verdicts_path"],
        message:
          "Select at least one engine report: certora_verdicts_path or aristotle_properties_path.",
      });
    if (value.out_path === undefined && value.analysis_path === undefined)
      context.addIssue({
        code: "custom",
        path: ["out_path"],
        message: "Select out_path when no analysis_path is given.",
      });
  });

export type SolanaFormalVerificationInput = z.infer<
  typeof solanaFormalVerificationInputSchema
>;

const verdictCountsSchema = z.strictObject(
  Object.fromEntries(FORMAL_VERDICTS.map((verdict) => [verdict, count])) as {
    [K in FormalVerdict]: typeof count;
  },
);

export type FormalVerdictCounts = z.infer<typeof verdictCountsSchema>;

export const formalPropertyResultSchema = z.strictObject({
  /** Certora rule name or Aristotle property name. */
  name: z.string(),
  verdict: formalVerdictSchema,
  /** The engine's own status spelling(s), as reported. */
  raw_status: z.string(),
  /** Counterexample note, failure reason, or leaf detail when reported. */
  detail: z.string().nullable(),
  /** Source location the engine attached, when any. */
  location: z.string().nullable(),
});

export type FormalPropertyResult = z.infer<typeof formalPropertyResultSchema>;

export const formalEngineReportSchema = z.strictObject({
  engine: formalEngineSchema,
  source_path: z.string(),
  source_sha256: digestSchema,
  /** Certora job id or Aristotle project id. */
  run_id: z.string(),
  /** Certora job status; null for engines that report none. */
  run_status: z.string().nullable(),
  results: z.array(formalPropertyResultSchema),
  counts: verdictCountsSchema,
  issues: z.array(z.string()),
});

export type FormalEngineReport = z.infer<typeof formalEngineReportSchema>;

export const solanaFormalVerificationResultSchema = z.strictObject({
  report_path: z.string(),
  report_sha256: digestSchema,
  artifact: z.strictObject({
    /** SHA-256 the reports are bound to; null when unbound. */
    elf_sha256: digestSchema.nullable(),
    program_id: z.string().nullable(),
    analysis_path: z.string().nullable(),
    binding: z.enum(["analysis", "declared", "unbound"]),
  }),
  engines: z.array(formalEngineReportSchema).min(1),
  totals: verdictCountsSchema,
  /**
   * `engine:name` for every property an engine proved. This is the whole
   * formally-verified claim, and it holds only under each engine's
   * documented assumptions.
   */
  formally_verified: z.array(z.string()),
  /** `engine:name` for every violated or sanity-failed property. */
  findings: z.array(z.string()),
  issues: z.array(z.string()),
  not_claimed: z.array(z.string()),
  /**
   * Per engine: whether its CLI's credential variable is set in this
   * process (presence only; the value is never read into output) and the
   * official commands that produce the report this tool ingests.
   */
  readiness: z.array(
    z.strictObject({
      engine: formalEngineSchema,
      credential_variable: z.string(),
      credential_present: z.boolean(),
      run_commands: z.array(z.string()),
    }),
  ),
});

export type SolanaFormalVerificationResult = z.infer<
  typeof solanaFormalVerificationResultSchema
>;
