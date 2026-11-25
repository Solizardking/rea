# Certora Prover for Solana programs

Adapted from the `certora-solana-fv` skill in [Solizardking/skills](https://github.com/Solizardking/skills/tree/main/skills/certora-solana-fv). REA ingests the verdicts with `solana_formal_verification`; this file covers producing them.

## Connect to Certora and set up the toolchain

- Create a Certora account at prover.certora.com and take the personal access key from the account pages. Get new style keys from app.certora.com when the CLI warns that a key is legacy.

- Pass the key to the prover process only through the CERTORAKEY environment variable. Never print it, log it, commit it, or write it into any file.

- Drive Solana verification through the `certoraSolanaProver` CLI. Since Certora Prover 8.1.0 `certoraRun` no longer accepts Solana targets ([release notes](https://docs.certora.com/en/latest/docs/prover/changelog/prover_changelog.html)); older notes below that say certoraRun mean certoraSolanaProver for Solana. Certora offers no official MCP server, and this CLI route is the one verified end to end on Solana, with the hosted platform and its REST API covered as a second surface below.

- Install certora-cli into a Python venv and follow the Solana installation page in the Certora docs for the prover and cargo-certora-sbf setup.

- Pin the Certora platform tools to a version Certora has actually published and pass it with the cargo tools version flag on every run. Version v1.53 is the latest published release and its linux tarball hashes to sha256 300a2d037de72bb0a8e3dafb6c173824ce28762d03c88dd8e8552a0aefa30035.

- Check the platform tools releases page before pinning anything newer. A conf that pins an unpublished version such as v1.58 cannot run at all.

- Run host builds with the 1.89.0 Rust toolchain selected through RUSTUP_TOOLCHAIN. Warm the cargo registry once online, then build offline against the warm cache.

## Know the hosted platform and its limits

- Read the hosted platform as three engines beside the classic prover. AutoProver infers intent from code and design documents, formalizes that intent into implementation independent properties, and compiles the properties into CVL rules the Certora Prover checks, while AutoFuzzer turns generated properties into Foundry tests.

- Treat AutoProver and AutoFuzzer as Solidity only today. AutoProver is in beta, and Rust support for both engines is planned for a future release rather than shipped, so never promise AutoProver or AutoFuzzer results for Rust code.

- Keep the classic certoraRun route with hand written CVLR specs as the verification path for Solana programs. The hosted engines do not replace it for Rust code.

- Run AI Auditor over Solana code and design documents today when a language agnostic review helps. It finds issues in code and documents in any language without a prover run, and its findings feed a threat model that sharpens the property list for later spec work.

- Treat an All in one run as Solidity bound. Its AutoProver and AutoFuzzer portions require Solidity contracts, and only its AI Auditor portion can inspect other languages.

- Consider Evaluate mode when a suite already exists and someone wants the specs judged. An Evaluate report opens with property coverage, CVL faithfulness scored as exact, partial, or wrong, and rule execution, and it adds spec coverage, scene soundness, tractability, and mutation testing sections when the evaluation produces them.

- State the Evaluate caveat plainly before proposing it for a Solana suite. Evaluate is documented inside the Solidity AutoProver pipeline, and whether it accepts Solana CVLR spec and conf files is not documented and has not been tested by us, so present it as a test to run against a suite and never as a confirmed capability.

## Connect through the REST API

- Create a scoped organization API key under API in the organization sidebar when an integration needs the REST surface, and send it as an Authorization Bearer header. Guard it with the same secrecy rules as CERTORAKEY.

- Plan key ownership before automating anything. A key is scoped to one organization and tied to its creator, and it stops working when the creator leaves the organization or is banned, so hold agent keys under an account that will stay.

- Enable Use Certora Prover on the key when the integration must run classic verification. Classic prover verification is available through the API on every plan including Free, and a key created without that permission cannot run it.

- Treat the version 2 launch endpoints as Solidity engine flows. The classic prover API path is the one relevant to Solana, and the CLI route in this skill remains the one verified end to end, so read [references/platform-and-api.md](certora-platform-and-api.md) for the endpoint list, the estimate and idempotency flow, the polling discipline, the error shape, and the rate buckets before building on the API.

- Budget a campaign from the right pot before launching anything. Hosted engine runs draw on a prepaid USD organization balance, failed runs that produce no billable output are free, and cancelled runs pay only for work completed, while classic prover verification draws on its own monthly free verification minutes plus metered billing, and neither allowance covers the other.

- Reach for Certora's GitHub Action installer only for the hosted engines. It installs AI Auditor, AutoProver, or AutoFuzzer workflows on connected repositories, only AI Auditor among them can read Rust code, and Solana prover suites keep the certoraRun in GitHub Actions pattern from the record section below.

## Survey the program and pin the artifact

- Read the whole program before writing any rule and establish what the code actually enforces, instruction by instruction. Write the survey down beside the specs.

- Treat any type, account, or error that no processor ever reads as unenforced, however official it looks. One surveyed program carried a verifier registry that existed as types and a PDA but was never read, so any key could authorize a proof.

- Record the base commit and the sha256 of the SBF build in the results file before submitting anything. Tie every later verdict to that pair.

- Dump a deployed program read only from its ProgramData account when verdicts must speak about the deployed artifact. Compare the dump against a fresh rebuild before claiming anything about deployed bytes.

- Compare the instruction stream in the .text section when a rebuild differs from the deployed bytes. A rebuild can differ only in embedded panic location path strings, relative in one build and absolute in the other, while the instruction stream stays identical.

## Write the spec suite

- Place the specs under src/certora inside the program crate and gate them behind a certora cargo feature. Keep the production build instruction identical with the feature off and prove that with a byte comparison of both builds.

- Group the rules by property so each group maps to one claim a reader can audit. Keep design models for unimplemented behavior in a separate conf, out of the proven set.

- Write every assumption down as a numbered axiom list in the specs. Typical entries cover hash determinism and collision resistance, a Groth16 verify oracle summary over the public inputs, CPI summaries for system transfers, sysvar fidelity, and a single invocation model with framework validation as a precondition.

- Model syscalls the prover cannot execute, such as sol_poseidon and the alt_bn128 operations, as summaries with stated contracts. Never let an unmodelled operation pass silently as if it were proven.

- Build nondeterministic byte arrays with a local nondet_bytes helper that fills the array element by element. The cvlr nondet library implements Nondet only for scalars, bool, and Option, so a direct nondet call on a fixed size byte array fails to compile.

- Fix spec crate compile errors in the harness construction only. Never weaken, delete, or route around an assertion to make a run pass, and record any counterexample verbatim as a finding.

## Pass the local gates and submit

- Run the host check with the certora feature enabled and require exit 0 before anything else. Run cargo certora-sbf with the pinned tools version and the certora feature next and require exit 0 again.

- Read the frame analysis in the gate output and record every function whose frame passes the 4,096 byte frame offset guideline. Large Anchor account deserialization is the usual cause, and oversize frames predict a cloud encoding failure.

- Submit one property group first and read its verdicts before sending the rest. Stop and diagnose when the first group fails at encoding instead of burning runs on identical failures.

- Drive submissions with the top level run conf plus explicit rule name flags when per property confs fail to load. Per property confs that inherit through a files entry naming run.conf are rejected by certora-cli 8.20.3, and a process attribute in a conf is unknown to it.

- Pass the built .so file as the CLI positional argument for prebuilt mode. Reach for prebuilt mode or omit sources for private program source so the source never uploads to the cloud.

- Record every job ID in the results file as soon as a submission returns. Job reports live under prover.certora.com in the output path for the account and job.

## Read verdicts and keep the record

- Report VERIFIED only for rules the prover actually proved, and only under the documented assumptions. Use the wording formally verified under documented assumptions for those rules and nothing broader.

- Treat VIOLATED as a program finding and record the counterexample verbatim. Never edit a spec to make a counterexample go away.

- Treat UNKNOWN as no verdict at all. Rule encoding failures happen on the prover side before any solving and say nothing about the program, in either direction.

- Match encoding failures against the known walls before retrying. Read [references/troubleshooting.md](certora-troubleshooting.md) for the verbatim error signatures, the conf traps, and the toolchain traps.

- State the not claimed boundary in every report. Formal verification of program rules does not prove circuit correctness, a trusted setup, off chain or GPU execution, or end to end confidentiality unless those are separately in scope.

- Keep a RESULTS.md beside the specs and update it on every run with per rule verdicts, job links, the assumption list, and the not claimed boundary. Add a SURVEY.md from the survey step so the next agent inherits the code reading, not just the verdicts.

- Copy the two worked suites before starting a new one. The Dark Protocol suite is the Anchor worked example listed under Websites.

- Revisit the mutation testing inside Evaluate mode as a future check on spec quality. It injects bugs and reports whether a rule catches each one, and it stays a flagged idea rather than a step in this method until someone confirms Evaluate accepts Solana spec files.

- Wire the prover into GitHub Actions on pull requests plus a weekly schedule once the manual flow works, with CERTORAKEY stored as a repository secret. Keep the first runs manual until one property group returns real verdicts.

## Websites

- [Certora documentation](https://docs.certora.com/en/latest/docs/solana/installation.html) for the Solana installation page covering the prover, cargo-certora-sbf, and platform tools setup. Verify the pinned tools version against the releases page before a first run.

- [Certora Prover](https://prover.certora.com/) for the account, the personal access key, and the job reports after each submission. Carry the job ID from the CLI output and confirm the per rule verdicts on the report page.

- [Certora app](https://app.certora.com/) for new style API keys when the CLI flags an existing key as legacy.

- [Certora Solana platform tools releases](https://github.com/Certora/certora-solana-platform-tools/releases) for the published tools versions and their tarballs. Pin only versions listed there.

- [API Evangelist Certora profile](https://github.com/api-evangelist/certora) for an independent rating of Certora agent readiness, which it scores as human only. Read it as the reason this skill drives the CLI directly.

- [Dark Protocol Certora suite](https://github.com/Solizardking/dark-protocol/tree/feat/certora-cvlr-specs/dark-protocol/programs/dark-protocol/src/certora) for the worked Anchor example with 37 rules across seven properties, its survey, and its results file.

- [Certora AutoProver skill](https://github.com/certora/autoprover-skill) for Certora's own skill for writing specs first, which the hosted run form recommends when a repository lacks spec and conf files. It targets the Solidity pipeline, so borrow its spec writing habits rather than its toolchain.

- [Certora AutoProver repository](https://github.com/certora/AutoProver) for the open source local pipeline behind AutoProver test and rule generation. Read it to understand what the hosted engine generates before trusting a generated spec.

- [Certora Verification Language documentation](https://docs.certora.com/en/latest/docs/cvl) for the CVL reference behind the classic prover route. Check rule syntax and semantics there before blaming the prover for a spec error.

## Alternatives for better results

- Start with the property group whose rules use the smallest harness surface when a program is new to the prover. A clean verdict there proves the pipeline before the heavy groups expose encoding limits.

- Prefer the artifact dump and compare route over lockfile archaeology when a rebuild does not reproduce a deployed program. One read only dump plus a .text comparison settles whether the difference is cosmetic.

- Split a suite into a proven set and a design model set when part of the spec describes behavior the program does not implement yet. The split keeps every published claim tied to code that exists.
