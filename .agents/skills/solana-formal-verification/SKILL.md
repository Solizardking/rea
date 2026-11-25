---
name: solana-formal-verification
description: Formally verify Solana programs with REA — pin the deployed sBPF artifact, prove rules with the Certora Solana Prover (CVLR) or properties with Harmonic Aristotle (Lean 4) or QEDGen, and bind the verdicts to the analyzed artifact with solana_formal_verification. Use when someone wants formally verified claims about a Solana program, Lean 4 proofs, Certora rules, or an honest verified/violated/no-verdict report; skip it for plain decompilation (use solana-decompile).
---

# Solana formal verification

Formally verified REA: every claim names the exact artifact (SHA-256), the
engine, the rule or property, and the assumptions it holds under.

## Rule: verified means proved, nothing broader

- `verified` = the named engine proved that rule or property, under its
  documented assumptions, summaries and harnesses. Word it as "formally
  verified under documented assumptions".
- `violated` / `sanity-failed` = a finding. Record the counterexample
  verbatim; never edit a spec to make it go away.
- `timeout`, `error`, `in-progress`, `unresolved`, `unchecked`, `unknown` =
  no verdict in either direction.
- Every report carries a `not_claimed` boundary. Keep it in anything you
  publish.

## Workflow

1. **Pin the artifact.** Capture the program with REA (`analyze_solana_program`
   by `program_id` + `out_dir`, or a local `.so`; see the `solana-decompile`
   skill). Record the artifact SHA-256 and slot from `solana-analysis.json`.
2. **Tie source to bytes.** Formal tools verify source or a build. Rebuild the
   program and compare against the captured ELF (compare `.text` when panic
   path strings differ). Without that match, a verdict speaks about the
   rebuild, not the deployed program.
3. **Survey and write the spec.** Read what each instruction actually
   enforces; write `SPEC.md` (security goals, state model, operations,
   properties, trust boundary) before any rule. Treat types no processor reads
   as unenforced.
4. **Prove** with one or more engines:
   - **Certora Solana Prover** (CVLR rules in Rust): `CERTORAKEY` env only.
     Prefer prebuilt mode with the pinned `.so` so the source never uploads:
     `certoraSolanaProver <program.so> --rule <rule> ...`, then read the
     verdicts back with
     `prover-cli --job-id <job_id> --verdicts --format json --output certora-verdicts.json`.
     Details: [references/certora.md](references/certora.md),
     [platform and API](references/certora-platform-and-api.md),
     [troubleshooting](references/certora-troubleshooting.md).
   - **Harmonic Aristotle** (Lean 4 from Rust source): `ARISTOTLE_API_KEY`
     env only. `aristotle submit "<goal>" --project-dir <crate> --wait`, then
     `aristotle properties <project-id> --json > aristotle-properties.json`.
     Details: [references/aristotle.md](references/aristotle.md).
   - **QEDGen** (agent-written Lean 4 models with the `QEDGen.Solana` support
     library; Leanstral for hard `sorry`s via `MISTRAL_API_KEY`). Record the
     results by hand in `SPEC.md`; REA does not ingest QEDGen output yet.
     Details: [references/qedgen.md](references/qedgen.md).
5. **Bind and report** with REA:

   ```sh
   rea solana-formal-verification \
     --analysis-path /abs/out/solana-analysis.json \
     --verified-artifact-sha256 <sha256 of the .so the prover ran on> \
     --certora-verdicts-path /abs/certora-verdicts.json \
     --aristotle-properties-path /abs/aristotle-properties.json --json
   ```

   MCP: `solana_formal_verification` with the same fields. A declared
   artifact SHA-256 that differs from the analysis is refused. The tool
   writes `formal-verification.json` exclusively (never overwrites) with
   per-engine results, `formally_verified`, `findings`, `issues`,
   `not_claimed`, and `readiness` (whether each engine's credential variable
   is present, never its value, plus the commands that produce its report).

6. **Keep the record.** Commit `SPEC.md`, the specs, a `RESULTS.md` with job
   or project ids and per-rule verdicts, and the REA report. Never commit
   keys or `.env` files.

## Boundaries

- REA never submits a prover run, uploads source, or reads a credential
  value; it only normalizes reports you produced and binds them by SHA-256.
- Certora's hosted AutoProver/AutoFuzzer are Solidity-only today; for Solana
  use the classic prover with hand-written CVLR rules.
- Formal verification of program rules does not establish off-chain
  components, ZK circuits, trusted setups, key management or deployment
  configuration unless those are separately in scope.
- Paid runs (Certora metered minutes, Aristotle credits) need the owner's
  approval first.
