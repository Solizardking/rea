---
name: solana-decompile
description: Analyze and reconstruct Solana sBPF programs with REA — capture a deployed program's ELF by id or analyze a local capture, recover Anchor discriminator candidates and the syscall surface, and hand the leads to differential verification. Use when a claim depends on a Solana program's deployed bytecode rather than available source.
---

# Solana decompile

Use REA's `analyze_solana_program` when the ground truth is a deployed Solana
program: its source is unavailable, untrusted, or suspected to differ from
the deployed ELF. Do not use it for ordinary source-repository analysis.

## Workflow

1. **Capture.** Prefer an existing local capture when byte identity with a
   known on-chain state matters. Otherwise fetch by program id:
   `rea analyze-solana-program --program <id> --out <dir>` (or the MCP tool
   with `program_id` + `out_dir`). Intake is read-only `getAccountInfo` at
   finalized commitment through the BPF Loader Upgradeable ProgramData
   layout; the fetched ELF lands at `<out>/<program_id>.so`. Record the
   returned artifact SHA-256 and slot — they name exactly what you analyzed.
2. **Analyze.** Run the analyzer on the ELF (`--elf <path>`, optionally
   `--out <dir>` for `solana-analysis.json` and the full `disassembly.txt`).
   Read the Evidence: ELF sections/entrypoint, disassembly counts, undefined
   dynamic symbols (the `sol_*` syscall surface), bounded `.rodata` strings,
   and the handler candidate table.
3. **Map discriminators to candidate handlers.** Each handler row is an
   Anchor-style lead recovered from the `lddw` constant + register-compare
   dispatch idiom: discriminator bytes, constant/comparison addresses, and
   the branch target that enters the handler body. When an Anchor IDL or
   source names are available, confirm a lead by checking
   `sha256("global:<instruction_name>")[..8]` against the discriminator
   (account discriminators use the `account:` prefix). Leads that match no
   name stay labeled candidates — never rename them by guesswork.
4. **Hand off to differential verification.** Decompilation output is a
   reconstruction lead, never proof. Following the pumpfun-source model:
   rebuild or write the candidate implementation, then run it side-by-side
   with the captured original in a local VM (LiteSVM/Surfpool) over fixtures
   derived from real transactions, and compare resulting account bytes,
   return data, and errors. A handler counts as recovered only when its
   differential receipts pass; the discriminator scan alone does not
   establish behavior, account layouts, or arithmetic.

## Boundaries

- The analyzer never executes the target, builds transactions, or touches a
  wallet. RPC intake is the only network step and is read-only.
- Table dispatch, split 32-bit compares, and computed jumps are not
  recovered; an empty handler table is an unknown, not a negative result.
- `call` immediates are loader-resolved syscall/function hashes; the
  analyzer reports the dynamic-symbol surface instead of inventing names.
- Full sBPF-to-Rust lifting is out of scope. For deeper decompilation, feed
  the captured ELF (identity pinned by the Evidence SHA-256) to Ghidra/IDA
  through REA's native workflows and treat their output with the same
  lead-then-verify discipline.
