import { expect, it } from "vitest";

import {
  ARISTOTLE_ADAPTER,
  CERTORA_ADAPTER,
  FormalReportShapeError,
  sumCounts,
} from "./SolanaFormalVerification.js";

const SOURCE = { path: "/reports/r.json", sha256: "a".repeat(64) };

/** Shaped like Certora/ProverCLI `JobVerdicts.to_dict()`. */
const certoraVerdicts = {
  job_id: "0f1e2d3c4b5a",
  job_status: "SUCCEEDED",
  rules: {
    rule_withdraw_requires_owner: { counts: { VERIFIED: 3 }, leaves: [] },
    rule_conservation: {
      counts: { VERIFIED: 2, VIOLATED: 1 },
      leaves: [{ method: "withdraw", status: "VIOLATED", assert: null }],
    },
    rule_not_vacuous_deposit: {
      counts: { SANITY_FAILED: 1 },
      leaves: [
        { method: null, status: "SANITY_FAILED", assert: "rule_not_vacuous" },
      ],
    },
    rule_slow: { counts: { TIMEOUT: 1, VERIFIED: 1 } },
    rule_running: { counts: { RUNNING: 1 } },
  },
  counterexamples: [],
  report: {},
};

it("maps Certora leaf counts to rule verdicts with violation precedence", () => {
  const report = CERTORA_ADAPTER.parse(certoraVerdicts, SOURCE);
  const byName = Object.fromEntries(
    report.results.map((result) => [result.name, result]),
  );
  expect(byName["rule_withdraw_requires_owner"]?.verdict).toBe("verified");
  expect(byName["rule_conservation"]?.verdict).toBe("violated");
  expect(byName["rule_conservation"]?.detail).toBe("withdraw: VIOLATED");
  expect(byName["rule_not_vacuous_deposit"]?.verdict).toBe("sanity-failed");
  expect(byName["rule_slow"]?.verdict).toBe("timeout");
  expect(byName["rule_running"]?.verdict).toBe("in-progress");
  expect(report.run_id).toBe("0f1e2d3c4b5a");
  expect(report.counts.verified).toBe(1);
  expect(report.issues).toEqual([]);
});

it("flags verdicts from a Certora job that did not succeed", () => {
  const report = CERTORA_ADAPTER.parse(
    { ...certoraVerdicts, job_status: "HALTED" },
    SOURCE,
  );
  expect(report.issues.join(" ")).toContain("HALTED");
});

it("refuses a Certora document that is not prover-cli verdicts JSON", () => {
  expect(() => CERTORA_ADAPTER.parse({ rules: "nope" }, SOURCE)).toThrow(
    FormalReportShapeError,
  );
});

/** Shaped like aristotlelib `DeclarationPage` printed by `aristotle properties --json`. */
const aristotleProperties = {
  project_id: "proj_123",
  pagination_key: null,
  declarations: [
    {
      declaration_id: "d1",
      declaration_type_name: "PROPERTY",
      name: "vault_conservation",
      status: 3,
      status_name: "PROVED",
      source_file: "programs/vault/src/lib.rs",
      source_line: 42,
      unchecked: false,
    },
    {
      declaration_id: "d2",
      declaration_type_name: "PROPERTY",
      name: "withdraw_overflow",
      status: 2,
      status_name: "REFUTED",
      evidence_message: "amount = u64::MAX wraps",
      unchecked: false,
    },
    {
      declaration_id: "d3",
      declaration_type_name: "PROPERTY",
      name: "close_once",
      status: 3,
      status_name: "PROVED",
      unchecked: true,
    },
    {
      declaration_id: "d4",
      declaration_type_name: "PROPERTY",
      name: "budget_cut",
      status: 6,
      status_name: "FAILED",
      failure_reason_name: "OUT_OF_BUDGET",
    },
    {
      declaration_id: "d5",
      declaration_type_name: "DEFINITION",
      name: "VaultState",
      status: 0,
      status_name: "UNKNOWN",
    },
    {
      declaration_id: "d6",
      declaration_type_name: "PROPERTY",
      name: "old_prop",
      status: 4,
      status_name: "REMOVED",
    },
  ],
};

it("maps Aristotle statuses and treats unchecked verdicts as no verdict", () => {
  const report = ARISTOTLE_ADAPTER.parse(aristotleProperties, SOURCE);
  const byName = Object.fromEntries(
    report.results.map((result) => [result.name, result]),
  );
  expect(Object.keys(byName).sort()).toEqual([
    "budget_cut",
    "close_once",
    "vault_conservation",
    "withdraw_overflow",
  ]);
  expect(byName["vault_conservation"]?.verdict).toBe("verified");
  expect(byName["vault_conservation"]?.location).toBe(
    "programs/vault/src/lib.rs:42",
  );
  expect(byName["withdraw_overflow"]?.verdict).toBe("violated");
  expect(byName["withdraw_overflow"]?.detail).toBe("amount = u64::MAX wraps");
  expect(byName["close_once"]?.verdict).toBe("unchecked");
  expect(byName["budget_cut"]?.verdict).toBe("unresolved");
  expect(byName["budget_cut"]?.detail).toBe("OUT_OF_BUDGET");
  expect(report.issues.join(" ")).toContain("1 removed property");
});

it("sums verdict counts across engines", () => {
  const total = sumCounts([
    CERTORA_ADAPTER.parse(certoraVerdicts, SOURCE).counts,
    ARISTOTLE_ADAPTER.parse(aristotleProperties, SOURCE).counts,
  ]);
  expect(total.verified).toBe(2);
  expect(total.violated).toBe(2);
  expect(total.unchecked).toBe(1);
});

it("names each engine's credential variable without reading it", () => {
  expect(CERTORA_ADAPTER.credentialVariable).toBe("CERTORAKEY");
  expect(ARISTOTLE_ADAPTER.credentialVariable).toBe("ARISTOTLE_API_KEY");
  for (const command of [
    ...CERTORA_ADAPTER.runCommands,
    ...ARISTOTLE_ADAPTER.runCommands,
  ])
    expect(command).not.toMatch(/KEY=|--api-key/u);
});
