# Harmonic Aristotle (Lean 4) for Solana programs

Aristotle is Harmonic's formal-verification agent: it reads uploaded C, Rust,
or Verilog, states properties, and proves or refutes them in Lean 4. This is
Harmonic's **Aristotle prover** (aristotle.harmonic.fun), not the unrelated
Harmonic company-research product.

Sources: [MCP & CLI](https://aristotle.harmonic.fun/docs/installation),
[SDK reference](https://aristotle.harmonic.fun/docs/api),
[Tracking properties](https://aristotle.harmonic.fun/docs/properties),
[harmonic-ai/aristotle](https://github.com/harmonic-ai/aristotle),
[aristotlelib on PyPI](https://pypi.org/project/aristotlelib/).

## Credentials

- In scripts and CI, set `ARISTOTLE_API_KEY` (from the dashboard's API keys
  page). It overrides a key stored by `aristotle login`. Never print it, log
  it, commit it, or pass it on a command line that is recorded.
- Interactively, `aristotle login` prints an approval link and code; a coding
  agent can relay the link so the key never appears in the conversation.
- Runs are billed to the organization the key belongs to. Get the owner's
  approval before starting a paid run.

## Produce a report REA can ingest

```sh
# Install the CLI (needs uv); or run once with uvx --from "aristotlelib>=3" aristotle
uv tool install aristotlelib

# Upload the program crate (source in Rust) and wait for the run to finish
aristotle submit "Prove the vault conserves lamports across deposit and withdraw" \
  --project-dir ./programs/vault --wait

# Read the property table as JSON (aristotlelib DeclarationPage)
aristotle properties <project-id> --json > aristotle-properties.json
```

Then bind it to the analyzed artifact:

```sh
rea solana-formal-verification \
  --analysis-path /abs/out/solana-analysis.json \
  --aristotle-properties-path /abs/aristotle-properties.json --json
```

## Reading statuses

| Aristotle `status_name`         | REA verdict   | Meaning                                                                                             |
| ------------------------------- | ------------- | --------------------------------------------------------------------------------------------------- |
| `PROVED`                        | `verified`    | Proved under the assumptions the run summary lists                                                  |
| `PROVED` with `unchecked: true` | `unchecked`   | Never checked by Aristotle; no verdict                                                              |
| `REFUTED`                       | `violated`    | Counterexample and/or a proof of the negation                                                       |
| `FAILED`                        | `unresolved`  | Out of budget, system error, cancelled, or the proof failed the final check (`failure_reason_name`) |
| `IN_PROGRESS`                   | `in-progress` | No verdict yet                                                                                      |
| `REMOVED`                       | not reported  | Counted in the report issues                                                                        |

Definitions (`declaration_type_name: DEFINITION`) carry no verdict and are
skipped.

## Limits

- Aristotle verifies the source you upload, not deployed bytes. Pair it with
  a byte-identical rebuild of the captured ELF (see the main skill) before a
  verdict may speak about a deployed program.
- Uploading source sends it to Harmonic. Do not upload private program source
  without the owner's consent.
- Projects with only Lean files are not supported; upload the Rust crate.

## Swapping the Lean engine

REA's `FormalEngineAdapter` (`src/solana/SolanaFormalVerification.ts`) is the
seam: an adapter declares its engine id, the credential variable its own CLI
reads, the commands that produce its report, and a `parse` that maps the
report to REA verdicts. Replacing Aristotle with another Lean 4 service (for
example QEDGen + Leanstral, see [qedgen.md](qedgen.md)) is a new adapter plus
an input field; the binding, report, and Evidence stay unchanged.
