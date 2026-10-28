# Solana sBPF program analysis

`analyze_solana_program` / `analyze-solana-program` analyzes one Solana
program (sBPF ELF) from an explicitly selected source: a local ELF file, or a
program id fetched read-only through Solana JSON-RPC. It does not require an
active native binary target, never executes the program, and never builds,
signs, or broadcasts a transaction.

```sh
rea analyze-solana-program --elf ./pump_amm.so --json
rea analyze-solana-program --program pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA --out ./pump_amm --json
```

```json
{
  "name": "analyze_solana_program",
  "arguments": {
    "program_id": "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA",
    "out_dir": "/artifacts/pump_amm"
  }
}
```

## Intake

- `--elf <path>` analyzes the exact selected file. Path resolution failures
  (`ENOENT`, `ENOTDIR`, `ELOOP`, `ENAMETOOLONG`) are `invalid_request` issues;
  permission failures keep their own classification. Intake is bounded to
  64 MiB.
- `--program <id>` performs `getAccountInfo` at finalized commitment against
  `rpc_url`, `REA_SOLANA_RPC_URL`, or the public mainnet endpoint, in that
  order. BPF Loader Upgradeable programs resolve through their ProgramData
  account (tag 3 header: slot, optional upgrade authority, then the ELF);
  legacy-loader accounts holding an ELF directly are accepted as-is. The
  fetched ELF is materialized as `<out_dir>/<program_id>.so` and analyzed as
  that local file, so both modes share one artifact identity semantics.
  `out_dir` is therefore required with `--program`.
- When `out_dir` is selected in either mode, the provider also writes
  `solana-analysis.json` (the Evidence result) and `disassembly.txt` (the
  full linear-sweep disassembly) there.

## Evidence semantics

- Artifact SHA-256 covers the whole selected file, including any trailing
  account-capacity padding; `elf.trailing_bytes` reports how much of the file
  lies beyond the extents its ELF headers declare.
- ELF facts (class, byte order, machine, entrypoint, sections), dynamic
  symbols, and byte identity are observations. The record is nevertheless
  labeled `inferred`, because its headline output — the handler table — is
  inference.
- Handler candidates come from one dispatch idiom: a 64-bit constant loaded
  by `lddw` and consumed, before any overwrite, by a nearby register-register
  `jeq`/`jne`. That is the shape Anchor/rustc emits for instruction dispatch.
  Each candidate records the discriminator (the constant's little-endian
  bytes), the constant and comparison addresses, and the branch target.
- Syscall surface is the ELF's undefined dynamic symbols (`sol_*` names) plus
  call-site counts. `call` immediates are loader-resolved hashes and are not
  name-resolved by this analyzer.
- Disassembly is a linear sweep by the bundled sBPF decoder
  (`rea-sbpf-decoder`). It is not a Ghidra/IDA-grade lift: no control-flow
  recovery, Rust source, types, or account layouts are produced.

## Limitations

- Table dispatch, split 32-bit discriminator compares, and computed jumps
  are not recovered; an empty handler list does not prove a program has no
  callable interface.
- A fetched program reflects the endpoint's finalized state at call time; it
  may differ from an earlier capture if the program was upgraded.
- Discriminator candidates are reconstruction leads. Behavior parity with a
  deployed program is established only by differential tests against the
  captured original (the pumpfun-source model), never by this scan alone.

## 1-byte tag dispatch (Shank/Borsh native programs)

`tag_dispatch` lists compare trees over a byte loaded with `ldxb` (the shape
rustc/LLVM-BPF emits for a `match` on a Borsh enum discriminant; BPF has no
jump tables). The scan walks the tree with value-range narrowing and reports,
per tree, the load address, each tag's leaf target, and the default
(invalid-tag) arm. Inner enum matches also appear; the instruction dispatch is
the tree whose arity matches the program's IDL. On Metaplex Core the tree at
`0x1d608` recovers all 42 tags (0..41). `scripts/solana-milestone1.mjs` runs
the full offline loop (pinned ELF + IDL, LiteSVM receipts, scoreboard).
