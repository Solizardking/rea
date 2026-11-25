---
name: ree
description: Reverse engineer any target (firmware, APKs, desktop apps, websites, Solana programs) evidence-first with the REA hub in the Solizardking fork plus specialist engines like GhidraMCP and mitmproxy. Use when asked to reverse engineer, decompile, audit or explain how something works end to end, including Solana programs that need differential or formal verification.
---

# REE — Reverse Engineer Everything

- REE is the user's reverse engineering method. It pairs the REA hub from his fork (github.com/Solizardking/rea, cloned at `~/workspace/rea`) with the device workflow from @cabbitar's setup article (x.com/cabbitar/status/2119392619327590507, Nov 8 2026).

- Work evidence-first. Tag every finding KNOWN, LIKELY or UNKNOWN, and never fill in a missing name, type or behavior from decompiled output without evidence behind it.

- Only examine targets the user owns or is allowed to examine. Run unknown binaries in a VM or sandbox, never on the main machine, and never work on the only copy of a firmware image or capture.

## The stack

- Treat REA as the hub. Ask REA the question first and let it route to the right domain under `~/workspace/rea/src/` (android, browser, dotnet, electron, evm, firmware, frida, ghidra, hopper, ida, javascript, native, solana, wasm and more).

- Reach for a specialist engine only when REA asks for it or the target demands it. Starting with the hardest tool first is the classic way to burn a run.

- Install or refresh the hub with `npx rea-agents setup` (needs Node.js 22.x). Update later with `npx rea-agents@latest setup`.

- Use the fork, not upstream, for the user's work. His fork carries the Solana domain (`src/solana`) with batch program analysis, the deep-decompiler handoff and differential-verification receipts, and the Certora/Aristotle formal-verification report (`solana_formal_verification`, see the `solana-formal-verification` skill).

- The REA skill shipped in the repo lives at `.agents/skills/reverse-engineer-anything`. Read it for the full MCP tool catalog before inventing calls.

## Set up the workspace

- Give every target its own folder with `target/` for the artifact, `scratch/` for working files and `notes/` for findings.

- Keep `target/` read-only. Firmware images, APKs, app bundles and captures go in untouched, and all derived work lands in `scratch/` or `notes/`.

- Write the ground rules into the folder before starting. State the evidence tags, the read-only rule and what the user wants answered, so a later session inherits them.

- Drop the artifact in `target/` and open with the inventory prompt before any deep dive.

## Pick the engine for the target

- Firmware: pull the vendor firmware, unpack with Binwalk or Unblob through REA, then disassemble in Ghidra and read structures with the ImHex pattern language.

- Native binaries: use Ghidra with GhidraMCP (github.com/LaurieWired/GhidraMCP, Ghidra 12.1.4 from ghidra-sre.org, needs a JDK) so the agent can drive the disassembly. Keep GhidraMCP on its default port 8080.

- Network behavior: run mitmproxy on port 8082, never 8080, because GhidraMCP owns 8080. Point the device Wi-Fi proxy at the laptop on 8082, install the cert from mitm.it on the device, and save the capture with `mitmdump -p 8082 --set hardump=./target/capture.har`, which REA can read back.

- Android: read the APK with jadx and Apktool for the manifest, resources and permissions, use REA headless JADX for static analysis, and hook live behavior with Frida on the user's own build or emulator.

- Desktop apps: analyze Electron apps through REA with `npx -y rea-agents@latest analyze-javascript-application /absolute/path/to/app --json`, open .NET and Unity builds in ILSpy or dnSpyEx, and use a debugger such as x64dbg on Windows only when static analysis stalls.

- Symbolic questions: use angr when the question is which input reaches a given line, not for general reading.

- Websites and web apps: crawl the public surface, read the shipped JavaScript bundles, and map the API calls the client actually makes. The user's bubblemaps.io and percolator-launch teardowns followed this route.

- Solana programs: use the fork's `src/solana` domain. Capture the ELF with `analyze_solana_program` (read-only RPC by program id, or a local `.so`), recover instruction discriminators and account layouts, and keep the corpus in the pumpfun-source style tree (audit, binaries, docs, evidence, localnet, outputs, programs, repro, research, scripts).

## Run the analysis loop

- Inventory first. Ask REA what kind of target is in `./target`, its format, architecture and framework, and the 10 most interesting parts to read first.

- Trace one feature at a time. Follow the entry point and call chain for a single behavior instead of skimming the whole binary.

- Write findings to `notes/findings.md` as you go, each with its evidence tag and the artifact or offset that backs it.

- Turn findings into a spec. From `notes/findings.md`, write `notes/SPEC.md` with inputs, outputs and edge cases in plain words.

- On Solana, run the loop as pin capture, static recovery, interface synthesis, state recovery, then differential verification (`solana_receipts`) and, where proofs are wanted, formal verification bound to the same artifact (`solana_formal_verification`), and keep an evidence scoreboard of what is proven versus assumed.

## Verify and rebuild

- Never trust pseudocode blindly. Check every LIKELY or UNKNOWN item by hand against the disassembly, a capture or a live run before it goes in the spec.

- Verify by differential testing where possible. Run the recovered behavior against the real target or a localnet fork and record where they diverge.

- Rebuild clean-room when the user wants a feature recreated. Work from visitor-visible behavior (screenshots, layout, observable I/O) by default, and read code directly only for the user's own private targets.

## Websites

- [The setup article](https://x.com/cabbitar/status/2119392619327590507) for the original device workflow this skill is built on. Carry the target type into the read and verify tool versions against the tools' own pages.

- [rea.tools](https://rea.tools/) for REA guides and showcases from upstream. The user's fork on GitHub is the source of truth for his build.

- [Ghidra](https://ghidra-sre.org/) for the current Ghidra release and JDK requirements.
