import {
  aristotlePropertiesSchema,
  type AristotleProperties,
  certoraVerdictsSchema,
  FORMAL_VERDICTS,
  type FormalEngine,
  type FormalEngineReport,
  type FormalPropertyResult,
  type FormalVerdict,
  type FormalVerdictCounts,
} from "../domain/solana/solanaFormalVerification.js";

/** An engine report that does not match its documented output shape. */
export class FormalReportShapeError extends Error {}

/**
 * One formal-verification engine: how its machine-readable output maps to
 * REA's normalized verdicts. Engines are swappable: a replacement prover
 * (for example another Lean 4 service in place of Harmonic Aristotle) only
 * needs an adapter with the same contract.
 */
export interface FormalEngineAdapter {
  readonly engine: FormalEngine;
  /** Environment variable the engine's own CLI reads its key from; REA never reads its value. */
  readonly credentialVariable: string;
  /** Official commands that produce the report this adapter parses. */
  readonly runCommands: readonly string[];
  parse(
    document: unknown,
    source: { readonly path: string; readonly sha256: string },
  ): FormalEngineReport;
}

const zeroCounts = (): FormalVerdictCounts =>
  Object.fromEntries(FORMAL_VERDICTS.map((verdict) => [verdict, 0])) as {
    [K in FormalVerdict]: number;
  };

export const countVerdicts = (
  results: readonly { readonly verdict: FormalVerdict }[],
): FormalVerdictCounts => {
  const counts = zeroCounts();
  for (const result of results) counts[result.verdict] += 1;
  return counts;
};

export const sumCounts = (
  all: readonly FormalVerdictCounts[],
): FormalVerdictCounts => {
  const total = zeroCounts();
  for (const counts of all)
    for (const verdict of FORMAL_VERDICTS) total[verdict] += counts[verdict];
  return total;
};

const shapeIssues = (
  issues: readonly { path: PropertyKey[]; message: string }[],
) =>
  issues
    .slice(0, 8)
    .map((issue) => `${issue.path.map(String).join(".")}: ${issue.message}`)
    .join("; ");

/**
 * Certora leaf statuses in the precedence a rule verdict takes: a single
 * violated leaf makes the rule violated, and a rule is verified only when
 * every leaf is VERIFIED.
 */
const CERTORA_PRECEDENCE: readonly [string, FormalVerdict][] = [
  ["VIOLATED", "violated"],
  ["SANITY_FAILED", "sanity-failed"],
  ["ERROR", "error"],
  ["TIMEOUT", "timeout"],
  ["RUNNING", "in-progress"],
  ["PENDING", "in-progress"],
  ["UNKNOWN", "unknown"],
];

const certoraRuleVerdict = (counts: Readonly<Record<string, number>>) => {
  const present = Object.entries(counts).filter(([, n]) => n > 0);
  if (present.length === 0) return "unknown" as const;
  for (const [status, verdict] of CERTORA_PRECEDENCE)
    if ((counts[status] ?? 0) > 0) return verdict;
  return present.every(([status]) => status === "VERIFIED")
    ? ("verified" as const)
    : ("unknown" as const);
};

/** Certora Prover (certoraSolanaProver / certoraRun) verdicts via Certora's prover-cli. */
export const CERTORA_ADAPTER: FormalEngineAdapter = {
  engine: "certora",
  credentialVariable: "CERTORAKEY",
  runCommands: [
    "certoraSolanaProver <program.so> --rule <rule> [<rule> ...]  # prebuilt mode: source stays local",
    "prover-cli --job-id <job_id> --verdicts --format json --output certora-verdicts.json",
  ],
  parse(document, source) {
    const parsed = certoraVerdictsSchema.safeParse(document);
    if (!parsed.success)
      throw new FormalReportShapeError(
        `Certora report is not prover-cli --verdicts JSON: ${shapeIssues(parsed.error.issues)}`,
      );
    const value = parsed.data;
    const issues: string[] = [];
    const results: FormalPropertyResult[] = Object.entries(value.rules)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([name, rule]) => {
        const leaves = rule.leaves ?? [];
        const failing = leaves.filter((leaf) => leaf.status !== "VERIFIED");
        return {
          name,
          verdict: certoraRuleVerdict(rule.counts),
          raw_status: Object.entries(rule.counts)
            .map(([status, n]) => `${status} ${String(n)}`)
            .join(", "),
          detail:
            failing.length === 0
              ? null
              : failing
                  .slice(0, 16)
                  .map(
                    (leaf) =>
                      `${leaf.method ?? leaf.assert ?? name}: ${leaf.status}`,
                  )
                  .join("; "),
          location: null,
        };
      });
    if (value.job_status !== "SUCCEEDED")
      issues.push(
        `Certora job ${value.job_id} reports job_status ${value.job_status}; verdicts from an unfinished or failed job are partial.`,
      );
    if (results.length === 0)
      issues.push(`Certora job ${value.job_id} reports no rules.`);
    return {
      engine: "certora",
      source_path: source.path,
      source_sha256: source.sha256,
      run_id: value.job_id,
      run_status: value.job_status,
      results,
      counts: countVerdicts(results),
      issues,
    };
  },
};

const ARISTOTLE_STATUS: Readonly<Record<string, FormalVerdict>> = {
  PROVED: "verified",
  REFUTED: "violated",
  FAILED: "unresolved",
  IN_PROGRESS: "in-progress",
  UNKNOWN: "unknown",
};

type AristotleDeclaration = AristotleProperties["declarations"][number];

const aristotleLocation = (declaration: AristotleDeclaration) => {
  const file = declaration.source_file ?? null;
  if (file === null) return null;
  const line = declaration.source_line ?? null;
  return line === null ? file : `${file}:${String(line)}`;
};

/** One Aristotle property as an REA result; an unchecked proof or refutation is no verdict at all. */
const aristotleResult = (
  declaration: AristotleDeclaration,
): FormalPropertyResult => {
  const mapped = ARISTOTLE_STATUS[declaration.status_name] ?? "unknown";
  const unchecked = declaration.unchecked === true;
  const verdict: FormalVerdict =
    unchecked && (mapped === "verified" || mapped === "violated")
      ? "unchecked"
      : mapped;
  return {
    name: declaration.name,
    verdict,
    raw_status: unchecked
      ? `${declaration.status_name} (unchecked)`
      : declaration.status_name,
    detail:
      declaration.status_name === "FAILED"
        ? (declaration.failure_reason_name ?? null)
        : (declaration.evidence_message ?? null),
    location: aristotleLocation(declaration),
  };
};

/** Harmonic Aristotle (Lean 4) property verdicts via `aristotle properties --json`. */
export const ARISTOTLE_ADAPTER: FormalEngineAdapter = {
  engine: "aristotle",
  credentialVariable: "ARISTOTLE_API_KEY",
  runCommands: [
    'aristotle submit "<what to prove>" --project-dir <program-crate> --wait',
    "aristotle properties <project-id> --json > aristotle-properties.json",
  ],
  parse(document, source) {
    const parsed = aristotlePropertiesSchema.safeParse(document);
    if (!parsed.success)
      throw new FormalReportShapeError(
        `Aristotle report is not \`aristotle properties --json\` output: ${shapeIssues(parsed.error.issues)}`,
      );
    const value = parsed.data;
    const issues: string[] = [];
    const results: FormalPropertyResult[] = [];
    let removed = 0;
    for (const declaration of value.declarations) {
      if (
        declaration.declaration_type_name !== undefined &&
        declaration.declaration_type_name !== "PROPERTY"
      )
        continue;
      if (declaration.status_name === "REMOVED") {
        removed += 1;
        continue;
      }
      results.push(aristotleResult(declaration));
    }
    if (removed > 0)
      issues.push(
        `Aristotle project ${value.project_id} lists ${String(removed)} removed propert${removed === 1 ? "y" : "ies"}; they are not reported.`,
      );
    if (results.length === 0)
      issues.push(
        `Aristotle project ${value.project_id} reports no properties.`,
      );
    results.sort((left, right) => left.name.localeCompare(right.name));
    return {
      engine: "aristotle",
      source_path: source.path,
      source_sha256: source.sha256,
      run_id: value.project_id,
      run_status: null,
      results,
      counts: countVerdicts(results),
      issues,
    };
  },
};

export const FORMAL_ENGINE_ADAPTERS: Readonly<
  Record<FormalEngine, FormalEngineAdapter>
> = { certora: CERTORA_ADAPTER, aristotle: ARISTOTLE_ADAPTER };

/** What no engine verdict here establishes, stated in every report. */
export const FORMAL_NOT_CLAIMED: readonly string[] = [
  "Verified means proved by the named engine under that engine's documented assumptions, summaries and harnesses; it is not a claim about properties no rule or property states.",
  "Engine verdicts are read from caller-supplied report files; REA did not run the prover, and a report is bound to an artifact only through the SHA-256 recorded here.",
  "Violated, sanity-failed and refuted results are findings to triage; timeout, error, in-progress, unresolved, unchecked and unknown are no verdict in either direction.",
  "Formal verification of program rules does not establish off-chain components, ZK circuit correctness, trusted setups, key management or deployment configuration.",
];
