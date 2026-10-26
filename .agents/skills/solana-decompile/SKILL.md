---
name: solana-decompile
description: Analyze a deployed Solana sBPF program with REA's analyze_solana_program — capture its ELF (solana program dump, local .so, or read-only fetch by program id), recover Anchor discriminator candidates, syscall surface and strings, cross-check against an IDL, and hand leads to differential verification. Use when a claim depends on a Solana program's deployed bytecode rather than available or trusted source; skip it for ordinary source-repository analysis.
---

# Solana decompile

Use when the ground truth is a deployed Solana program: its source is
unavailable, untrusted, or suspected to differ from the on-chain ELF.

## Rule: a lead, never proof

Every handler row is a reconstruction **lead**. It does not establish
behavior, account layouts, or arithmetic. A handler counts as recovered only
when a rebuilt implementation passes differential tests against the captured
original. Never rename an unmatched candidate by guesswork.

## Call it

MCP tool `analyze_solana_program` (input is a strict object; pick exactly one source):

| Input        | Type                        | Notes                                                                                      |
| ------------ | --------------------------- | ------------------------------------------------------------------------------------------ |
| `path`       | absolute local path         | sBPF ELF to analyze. Mutually exclusive with `program_id`.                                 |
| `program_id` | base58 pubkey (32–44 chars) | Fetched read-only via JSON-RPC (BPF Loader Upgradeable → ProgramData). Requires `out_dir`. |
| `rpc_url`    | URL                         | Only with `program_id`. Default: `REA_SOLANA_RPC_URL`, else public mainnet.                |
| `out_dir`    | absolute local path         | Receives `<program_id>.so` (program-id intake), `solana-analysis.json`, `disassembly.txt`. |

CLI equivalent:

```sh
rea analyze-solana-program --elf ./pump_amm.so --out ./out
rea analyze-solana-program --program <PROGRAM_ID> --out ./out [--rpc-url <URL>]
```

The tool never executes the target, builds transactions, or touches a wallet.
RPC intake is the only network step.

## Workflow

1. **Capture.** Prefer a pinned local capture when byte identity matters:
   `solana program dump <PROGRAM_ID> ./program.so` (Solana CLI), then pass
   `path`/`--elf`. Otherwise fetch by `program_id` with an `out_dir`.
2. **Pin identity.** Record `artifact.sha256`, `artifact.bytes`, and, for RPC
   intake, `artifact.slot` and `artifact.program_data_account`. SHA-256 covers
   the whole file, including trailing account-capacity padding
   (`elf.trailing_bytes`), so compare captures only by the same method.
3. **Check decode health.** `disassembly.coverage` should be `complete` and
   `disassembly.unknown_opcodes` should be 0. Otherwise treat every downstream
   row as suspect.
4. **Read the dispatch map.** Each `handlers[]` row has `discriminator`
   (16 hex chars, little-endian bytes), `constant_address`,
   `constant_file_offset`, `comparison_address`, `branch` (`jeq`/`jne`),
   `branch_target` (entry into the handler body), and the two registers.
5. **Cross-check with the IDL if one exists.** For each instruction name,
   compute `sha256("global:<instruction_name>")[..8]` (accounts use
   `account:<Name>`) and match it against `discriminator`. Label matches by
   name; leave the rest as `candidate`.
6. **Survey the surface.** `syscalls.dynamic_symbols` lists the `sol_*`
   syscalls imported; `strings.relevant` gives bounded `.rodata` strings
   (error messages, seeds, log text) with file offsets.
7. **Hand off.** Rebuild or write the candidate handler, run it beside the
   captured original in a local VM (LiteSVM/Surfpool) over fixtures from real
   transactions, and compare account bytes, return data and errors. Only
   passing differential receipts promote a lead to recovered.

## Interpreting output

- More candidates than real instructions is normal: any 64-bit constant
  compared against a register (e.g. bitmasks) can appear. IDL matches separate them.
- An empty `handlers` list is an unknown, not a negative result. The program may
  use table dispatch or split compares, or it may not be Anchor at all.
- `call` immediates are loader-resolved hashes. Use the dynamic-symbol list
  instead of inventing syscall names.
- Read `limitations[]` in every report; it records per-run caveats.

## Known limits

- Only the `lddw` constant + register-compare (`jeq`/`jne`, within 8
  instructions) dispatch idiom. Table dispatch, split 32-bit compares and
  computed jumps aren't recovered.
- Linear-sweep disassembly only. No sBPF→Rust lifting, types, control flow
  or account layouts.
- One program per invocation.

## Worked example: pump_amm (figures as reported by PR #1)

Input: `{ "path": "/artifacts/pump_amm.so" }` (or `program_id`
`pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA` with `out_dir`).

As reported by the PR:

- ELF sha256 `6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7`.
- 139,524 instructions decoded, 0 unknown opcodes. 14 `sol_*` syscall symbols.
- 55 handler candidates against 38 real handlers.
- `create_config` → discriminator `c9cff3724b6f2fbd`, constant 900392,
  comparison 900408, branch target 901912. This matches pumpfun-source's
  independent IDL-based dispatch map.
- A live fetch by program id returned an ELF byte-identical to the capture.

Next step from here: confirm `sha256("global:create_config")[..8]` equals
`c9cff3724b6f2fbd`, then differentially test a rebuilt `create_config` before
calling it recovered.
