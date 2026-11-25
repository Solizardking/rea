# Troubleshooting Certora runs on Solana

Field record from two suites run between 2026-11-13 and 2026-11-24, the RedPill verifier (native Rust, 50 rules) and Dark Protocol (Anchor, 37 rules). Every failure below happened in practice and is recorded with its verbatim signature.

## The three encoding walls

- Watch for error 3308 with the text "illegal dereference of an absolute address" from verifier.RuleEncodingException. It is a pointer analysis failure in the SBF to TAC translation, raised on ordinary Vec operations in the spec harness such as extend_from_slice over temporary byte arrays and Vec push in a byte loop.

- Watch for error 3006 with the text "illegal store of a stack pointer" from the same exception. It appears on slice to_vec conversions after the harness is rewritten away from Vec growth, so rewriting the builder tends to move the failure site rather than clear it.

- Read the prover help text for 3308 before improvising fixes. It prescribes the aggressive global detection prover option and correct application of the summaries and inlining files, and both were tried without clearing the wall on the RedPill suite.

- Watch for error 6000 reporting that the current stack size is 4096 and the stack offset exceeded the max offset, with the excess stated per rule. Large program frames cause it, and the local frame analysis names the functions in advance.

- Compare the cloud excess against the local frame analysis numbers before concluding anything. The encoding site reports its own excess, so the two numbers describe the same wall without matching one to one.

## The doubled env path warning

- Search every job report for the WARN SBF line about a problem reading the env files under a doubled .certora_sources prefix. The cloud prover builds the path with the prefix twice for files declared in the package metadata or the conf, in sources and prebuilt modes alike.

- Treat the warning as a prime suspect whenever Vec operations fail encoding. The vendored env files cvlr_inlining.txt and cvlr_summaries.txt carry exactly the summaries that model the failing operations, such as turning a raw vec reserve into a heap pointer.

- Record the warning as a suspect to raise with Certora support or a newer certora-cli, not as a proven cause. A negative cannot be proven from outside the prover.

- Expect the warning in both suites and in every job. It appeared in six of six RedPill jobs and in the Dark Protocol job, so it is pipeline wide rather than suite specific.

## Conf traps in certora-cli 8.20.3

- Expect per property confs to be rejected when they inherit through a files entry that names run.conf. The CLI fails instantly with the message that run.conf does not end with .so, because it expects the files entry to name a built program.

- Run the top level run.conf directly with explicit rule name flags instead. Take the rule lists from the per property confs so the grouping survives even though the conf files do not load.

- Expect a conf carrying a process attribute to be rejected as an unknown attribute. Submit prebuilt runs by passing the .so as the positional file argument with the env files, sanity, and timeout given as flags.

- Leave the conf files unedited when a trap fires and note the trap in the results file. The working invocation belongs in the record, and a later CLI version may accept the original confs again.

## Toolchain traps

- Refuse to pin a platform tools version that the releases page does not list. The RedPill confs pinned v1.58, which Certora has never published, and the run could not start until v1.53 was selected with the CLI override flag.

- Verify the tools tarball hash before installing. The v1.53 linux tarball is 550,926,443 bytes and hashes to sha256 300a2d037de72bb0a8e3dafb6c173824ce28762d03c88dd8e8552a0aefa30035.

- Select the 1.89.0 host toolchain through RUSTUP_TOOLCHAIN for every build. A default older cargo cannot parse an edition 2024 workspace and fails before reaching the specs.

- Warm the cargo registry online once, then run cargo offline against the cache. Registry stalls under a flaky egress look like spec failures and are not.

- Expect a local target directory symlink to matter on constrained volumes. cargo-certora-sbf computes relative paths from the workspace, and a plain CARGO_TARGET_DIR override can break that computation.

## Spec crate traps

- Replace every nondet call on a fixed size byte array with an element wise helper. cvlr-nondet implements Nondet only for scalars, bool, and Option in both 0.6.0 and 0.6.2, and the missing array impl cost 75 of 83 errors in the first RedPill compile.

- Convert key types at the boundary when the program and the harness disagree. Program helpers may return a solana program Pubkey while harness account specs take the pinocchio byte array form, and a to_bytes call at the binding site resolves it.

- Wrap unsafe reads in an explicit unsafe block under edition 2024. A bare assume_init_ref call is a hard error, not a warning.

- Anchor specific, from the Dark Protocol suite. Read bumps from the structs Anchor 0.32 actually generates, because it caches bumps only for init with seeds or untargeted bump constraints and leaves other bump structs empty.

- Anchor specific, continued. Read a custom error code from the program_error field of the boxed error wrapper, and leak harness account infos to a static lifetime when Anchor TryFrom impls demand it while keeping state sharing clones for post state reads.

## Artifact comparison method

- Dump the deployed program with a read only getAccountInfo call on its ProgramData account. Verify first that the program account points at that ProgramData and that its owner is the upgradeable loader.

- Trim the ELF by its own section headers. Account data runs longer than the ELF, and the trailing bytes are zero filled allocation slack.

- Hash the trimmed ELF and compare it with the rehearsal or release record. A match settles the deployed bytes outright.

- Disassemble both binaries with relocations applied when the hashes differ. Classify every differing operand by its effective target before calling the difference cosmetic or semantic.

- Expect the cosmetic pattern to concentrate in .rodata panic location strings, with .text operands differing only where they point at moved or repacked strings. Zero opcode, register, or branch offset differences is the bar for calling a delta cosmetic.

- Restate the claim discipline after any comparison. Verdicts may attach to the deployed program logic once source identity and instruction stream equivalence are proven, and byte identity claims still require an exact hash match or a prebuilt run on the dumped binary.

## Wiring invariance check

- Build the program with the certora feature off before and after adding the spec wiring. Compare the two binaries byte by byte.

- Expect a tiny residue when the wiring adds lines to a shared file. A three line module declaration shifted embedded panic line numbers by three in the Dark Protocol build, changing 21 bytes while the instruction stream stayed byte identical.

- Investigate any difference beyond line number shifts before proceeding. A real instruction change means the wiring leaked into production code.

## What a good run record contains

- Record the base commit, the SBF build hash and size, and the exact toolchain versions for every run.

- Record each job ID with its mode, its rule list, and its time window, plus the report link pattern for the account.

- Record dirty tree state honestly when a job carries an uncommitted harness change. The job metadata shows it, and the record should match.

- Record NOT-RUN as a status with its reason when a group is deliberately held. A held group with a stated precondition reads very differently from a forgotten one.

## Hosted platform and API failures

- Read references/platform-and-api.md when a failure involves the hosted engines or the REST API rather than a local prover run. Engine launch errors, estimate mismatches, key permission failures, and lifecycle states such as finalizing live there, and the prover walls above say nothing about them.
