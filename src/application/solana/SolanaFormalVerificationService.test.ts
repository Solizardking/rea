import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, it } from "vitest";

import { SolanaFormalVerificationService } from "./SolanaFormalVerificationService.js";
import { SolanaProgramService } from "./SolanaProgramService.js";
import { parseEvidence } from "../../domain/evidence.js";
import type { SolanaFormalVerificationResult } from "../../domain/solana/solanaFormalVerification.js";
import { SolanaFormalVerificationProvider } from "../../solana/SolanaFormalVerificationProvider.js";
import { SolanaProgramProvider } from "../../solana/SolanaProgramProvider.js";
import { solanaDispatchElf } from "../../../tests/fixtures/solana/elf.js";

const CERTORA = {
  job_id: "job-1",
  job_status: "SUCCEEDED",
  rules: {
    rule_owner_only: { counts: { VERIFIED: 2 } },
    rule_conservation: { counts: { VIOLATED: 1 } },
  },
};

const ARISTOTLE = {
  project_id: "proj-1",
  declarations: [
    {
      declaration_type_name: "PROPERTY",
      name: "no_overflow",
      status_name: "PROVED",
      unchecked: false,
    },
  ],
};

const service = (environment: NodeJS.ProcessEnv = {}) =>
  new SolanaFormalVerificationService(
    new SolanaFormalVerificationProvider(environment),
  );

const analyzed = async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-solana-fv-"));
  const elfPath = join(root, "program.so");
  await writeFile(elfPath, solanaDispatchElf());
  const outDir = join(root, "out");
  const analysis = await new SolanaProgramService(
    new SolanaProgramProvider(),
  ).inspect({ path: elfPath, out_dir: outDir });
  expect(analysis.ok).toBe(true);
  const analysisPath = join(outDir, "solana-analysis.json");
  const sha = (
    JSON.parse(await readFile(analysisPath, "utf8")) as {
      artifact: { sha256: string };
    }
  ).artifact.sha256;
  const certoraPath = join(root, "certora-verdicts.json");
  const aristotlePath = join(root, "aristotle-properties.json");
  await writeFile(certoraPath, JSON.stringify(CERTORA));
  await writeFile(aristotlePath, JSON.stringify(ARISTOTLE));
  return { root, analysisPath, sha, certoraPath, aristotlePath };
};

it("binds Certora and Aristotle verdicts to the analyzed artifact", async () => {
  const { analysisPath, sha, certoraPath, aristotlePath } = await analyzed();
  const result = await service({
    CERTORAKEY: "do-not-echo-this-value",
  }).normalize({
    analysis_path: analysisPath,
    verified_artifact_sha256: sha,
    certora_verdicts_path: certoraPath,
    aristotle_properties_path: aristotlePath,
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const evidence = parseEvidence(result.value);
  expect(evidence.operation).toBe("solana_formal_verification");
  const report = evidence.normalized_result as SolanaFormalVerificationResult;
  expect(report.artifact).toMatchObject({
    elf_sha256: sha,
    binding: "analysis",
  });
  expect(report.formally_verified).toEqual([
    "certora:rule_owner_only",
    "aristotle:no_overflow",
  ]);
  expect(report.findings).toEqual(["certora:rule_conservation"]);
  expect(report.totals.verified).toBe(2);
  expect(report.readiness).toEqual([
    expect.objectContaining({ engine: "certora", credential_present: true }),
    expect.objectContaining({ engine: "aristotle", credential_present: false }),
  ]);
  const written = await readFile(report.report_path, "utf8");
  expect(written).not.toContain("do-not-echo-this-value");
  expect(JSON.stringify(result.value)).not.toContain("do-not-echo-this-value");
  expect(report.report_path.endsWith("formal-verification.json")).toBe(true);
});

it("refuses verdicts declared against a different artifact", async () => {
  const { analysisPath, certoraPath } = await analyzed();
  const result = await service().normalize({
    analysis_path: analysisPath,
    verified_artifact_sha256: "0".repeat(64),
    certora_verdicts_path: certoraPath,
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error.message).toMatch(/across artifacts|invalid/iu);
});

it("never overwrites an earlier report", async () => {
  const { analysisPath, certoraPath } = await analyzed();
  const input = {
    analysis_path: analysisPath,
    certora_verdicts_path: certoraPath,
  };
  expect((await service().normalize(input)).ok).toBe(true);
  const second = await service().normalize(input);
  expect(second.ok).toBe(false);
});

it("records unbound verdicts with an explicit issue", async () => {
  const { root, aristotlePath } = await analyzed();
  const result = await service().normalize({
    aristotle_properties_path: aristotlePath,
    out_path: join(root, "fv", "report.json"),
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const report = parseEvidence(result.value)
    .normalized_result as SolanaFormalVerificationResult;
  expect(report.artifact.binding).toBe("unbound");
  expect(report.issues.join(" ")).toContain("not bound to any artifact");
});

it("rejects a request that selects no engine report", async () => {
  const { analysisPath } = await analyzed();
  const result = await service().normalize({ analysis_path: analysisPath });
  expect(result.ok).toBe(false);
});

it("rejects a malformed engine report", async () => {
  const { root, analysisPath } = await analyzed();
  const bad = join(root, "bad.json");
  await writeFile(bad, JSON.stringify({ declarations: "x" }));
  const result = await service().normalize({
    analysis_path: analysisPath,
    aristotle_properties_path: bad,
  });
  expect(result.ok).toBe(false);
});
