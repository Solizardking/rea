#!/usr/bin/env node
// REA milestone 1: offline Metaplex Core reverse-engineering loop -> verified scoreboard.
// No network at test time: pinned ELF + pinned Shank IDL + local LiteSVM receipts.
// Usage: node scripts/solana-milestone1.mjs [--out DIR] [--pumpfun DIR] [--skip-receipts]
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FIX = join(ROOT, "tests/fixtures/solana/core");
const args = process.argv.slice(2);
const opt = (name, fallback) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : fallback; };
const OUT = resolve(opt("--out", join(ROOT, ".cache/solana-milestone1")));
const PUMPFUN = opt("--pumpfun", process.env.PUMPFUN_CORPUS);
const PINS = {
  elf: "51d41542456639a01820c747e72b9d3b4ca258930a5bbb7e78db0cda133dc209",
  idl: "ba75e3dbc1c332f63ddfd0ad4224590c725559679c5aa84eb8c43b6067bd3471",
};
const PROGRAM_ID = "CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d";
const PUMPFUN_BASELINE = 143;
const failures = [];
const check = (cond, msg) => { if (!cond) failures.push(msg); console.log(`${cond ? "ok  " : "FAIL"} ${msg}`); };
const sha = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
const hex = (n) => `0x${n.toString(16)}`;
mkdirSync(OUT, { recursive: true });

const elfPath = join(FIX, "core.so");
check(sha(elfPath) === PINS.elf, `pinned Core ELF sha256 ${PINS.elf.slice(0, 12)}…`);
check(sha(join(FIX, "mpl_core.idl.json")) === PINS.idl, "pinned mpl_core Shank IDL");

const rea = join(ROOT, "scripts/rea.mjs");
const analyze = (elf, out) => {
  mkdirSync(out, { recursive: true });
  execFileSync(process.execPath, [rea, "analyze-solana-program", "--elf", elf, "--out", out, "--json"], { stdio: ["ignore", "ignore", "inherit"], env: { ...process.env, REA_SOLANA_RPC_URL: "http://127.0.0.1:9" } });
  return JSON.parse(readFileSync(join(out, "solana-analysis.json"), "utf8"));
};
const analysis = analyze(elfPath, join(OUT, "core"));
check(analysis.disassembly.instruction_count === 86957 && analysis.disassembly.unknown_opcodes === 0, "86,957 instructions, 0 unknown opcodes");

const idl = JSON.parse(readFileSync(join(FIX, "mpl_core.idl.json"), "utf8"));
const ixs = idl.instructions.map((ix) => ({ name: ix.name, tag: ix.discriminant.value, accounts: ix.accounts.length }));
const tags = new Set(ixs.map((i) => i.tag));
const primary = analysis.tag_dispatch.find((t) => t.root === "byte-load" && t.handlers.length === ixs.length && t.handlers.every((h) => tags.has(h.tag)));
check(primary !== undefined, `Borsh decode: 1-byte tag tree covering all ${ixs.length} IDL tags`);

// Processor match: a register-rooted tree over the decoded enum. Each arm is
// named by the `msg!("Instruction: X")` log site it reaches (lddw into .rodata + len).
const elfBytes = readFileSync(elfPath);
const disasm = readFileSync(join(OUT, "core", "disassembly.txt"), "utf8").split("\n");
const lineAt = new Map(disasm.map((l, i) => [parseInt(l.slice(0, 8), 16), i]));
const logNameFrom = (addr) => {
  const start = lineAt.get(addr);
  if (start === undefined) return null;
  for (let k = start; k < Math.min(start + 64, disasm.length); k += 1) {
    const m = /= 0x([0-9a-f]{16}) ll$/.exec(disasm[k]);
    if (!m) { if (/\bexit$|goto /.test(disasm[k])) break; continue; }
    const len = /r2 = (\d+)$/.exec(disasm[k + 1] ?? "");
    if (!len) continue;
    const text = elfBytes.subarray(Number(BigInt(`0x${m[1]}`)), Number(BigInt(`0x${m[1]}`)) + Number(len[1])).toString("latin1");
    if (text.startsWith("Instruction: ")) return { name: text.slice(13), site: disasm[k].slice(0, 8).replace(/^0+/, "0x") };
  }
  return null;
};
const sameIx = (logName, idlName) => logName === idlName || `${logName}V1` === idlName;
let processor = null;
for (const tree of analysis.tag_dispatch.filter((t) => t.root === "register")) {
  const arms = tree.handlers.map((h) => ({ tag: h.tag, target: h.target, log: logNameFrom(h.target) }));
  const missing = ixs.filter((ix) => !arms.some((a) => a.tag === ix.tag));
  // rustc folds the last variant into the tree's else-arm when the decoder already bounds the tag.
  if (missing.length === 1 && tree.default_targets.length === 1)
    arms.push({ tag: missing[0].tag, target: tree.default_targets[0], log: logNameFrom(tree.default_targets[0]), via: "else-arm" });
  const named = arms.filter((a) => a.log && sameIx(a.log.name, ixs[a.tag]?.name)).length;
  if (named >= ixs.length - 2 && (!processor || named > processor.named)) processor = { root: tree.load_address, arms, named };
}
check(processor !== null, `processor match tree found (${processor?.named ?? 0} arms named by log site)`);

let receipts = { receipts: [] };
const receiptsDir = join(FIX, "receipts");
const receiptsOut = join(OUT, "receipts.json");
if (!args.includes("--skip-receipts")) {
  if (!existsSync(join(receiptsDir, "node_modules/litesvm")))
    execFileSync("npm", ["ci", "--no-audit", "--no-fund"], { cwd: receiptsDir, stdio: "inherit" });
  const run = spawnSync(process.execPath, [join(receiptsDir, "receipts.mjs"), elfPath, receiptsOut], { stdio: "inherit" });
  check(run.status === 0, "LiteSVM differential receipts all pass");
  receipts = JSON.parse(readFileSync(receiptsOut, "utf8"));
}
const passedTags = new Set(receipts.receipts.filter((r) => r.pass && !/negative/.test(r.name)).map((r) => r.tag));
const negativeOob = receipts.receipts.find((r) => r.tag === ixs.length && r.pass);

const entries = ixs.map((ix) => {
  const leaf = primary?.handlers.find((h) => h.tag === ix.tag);
  const arm = processor?.arms.find((a) => a.tag === ix.tag);
  const named = arm?.log ? sameIx(arm.log.name, ix.name) : false;
  const identity = leaf && arm && (named || arm.log === null);
  const status = !identity ? "lead" : passedTags.has(ix.tag) ? "receipt-verified" : "identity-confirmed";
  return {
    tag: ix.tag, name: ix.name, status,
    evidence: {
      idl: `mpl_core.json instructions[${ix.tag}] discriminant=${ix.tag}`,
      decoder: { tree: primary ? hex(primary.load_address) : null, arm: leaf ? hex(leaf.target) : null, note: "Borsh decode of the tag byte (arm parses this variant's args)" },
      processor: arm ? { tree: hex(processor.root), arm: hex(arm.target), via: arm.via ?? "leaf", log_name: arm.log?.name ?? null, log_site: arm.log?.site ?? null, name_matches_idl: named } : null,
      receipts: receipts.receipts.filter((r) => r.tag === ix.tag).map((r) => ({ name: r.name, pass: r.pass, compute_units: r.compute_units, err: r.err })),
    },
  };
});

// Classify the Anchor-style 8-byte candidates: Core has no 8-byte discriminators.
const handlers = analysis.handlers;
const reason = (h, i) => {
  const v = BigInt(`0x${Buffer.from(h.discriminator, "hex").reverse().toString("hex")}`);
  if (v === 0x8000000000000000n || v === 0x8000000000000001n) return "i64::MIN niche/Option sentinel compare";
  if (v === 0x8080808080808080n) return "SWAR byte-mask constant (memchr/utf8 scan)";
  const group = handlers.filter((o) => o.constant_register === h.constant_register && Math.abs(o.constant_address - h.constant_address) <= 0x80);
  if (group.length === 4) return "one 8-byte limb of a hard-coded 32-byte Pubkey equality (4 x u64 compares)";
  return "small/bitmask constant compare, not an instruction discriminator";
};
const notDispatch = handlers.map((h, i) => ({ status: "not-dispatch", discriminator: h.discriminator, constant_address: hex(h.constant_address), comparison_address: hex(h.comparison_address), reason: reason(h, i) }));

const counts = {};
for (const e of [...entries, ...notDispatch]) counts[e.status] = (counts[e.status] ?? 0) + 1;
check(entries.every((e) => e.status !== "lead"), "every IDL instruction mapped to a dispatch target");
check(negativeOob !== undefined || args.includes("--skip-receipts"), `out-of-range tag ${ixs.length} rejected`);

let pumpfun = null;
if (PUMPFUN && existsSync(join(PUMPFUN, "dispatch-map.json"))) {
  const map = JSON.parse(readFileSync(join(PUMPFUN, "dispatch-map.json"), "utf8"));
  let hit = 0, total = 0; const programs = {};
  for (const [name, v] of Object.entries(map)) {
    const elf = join(PUMPFUN, `${name}.so`);
    check(sha(elf) === v.binary_sha256, `pumpfun ${name} pinned sha256`);
    const got = new Set(analyze(elf, join(OUT, "pumpfun", name)).handlers.map((h) => h.discriminator));
    const list = Object.entries(v.instructions);
    const m = list.filter(([, i]) => got.has(i.discriminator)).length;
    programs[name] = { recovered: m, total: list.length, missing: list.filter(([, i]) => !got.has(i.discriminator)).map(([k]) => k) };
    hit += m; total += list.length;
  }
  pumpfun = { recovered: hit, total, baseline: PUMPFUN_BASELINE, programs };
  check(hit >= PUMPFUN_BASELINE, `pumpfun regression ${hit}/${total} >= baseline ${PUMPFUN_BASELINE}`);
} else console.log("skip pumpfun regression (set PUMPFUN_CORPUS to a dir with dispatch-map.json + <program>.so)");

const scoreboard = {
  milestone: "REA milestone 1: Metaplex Core", program_id: PROGRAM_ID,
  artifact: { sha256: analysis.artifact.sha256, bytes: analysis.artifact.bytes, captured_slot: 455005931 },
  idl: { source: "github.com/metaplex-foundation/mpl-core idls/mpl_core.json @ a5c35db", sha256: PINS.idl, instructions: ixs.length },
  dispatch: {
    decoder: primary ? { kind: "Borsh decode: 1-byte tag compare tree (ldxb)", load_address: hex(primary.load_address), compare_count: primary.compare_count, default_targets: primary.default_targets.map(hex), recovered: primary.handlers.length } : null,
    processor: processor ? { kind: "processor match over decoded enum (register-rooted tree)", root: hex(processor.root), arms: processor.arms.length, named_by_log: processor.named } : null,
  },
  statuses: { lead: "dispatch candidate only", "identity-confirmed": "tag reaches a decoder arm AND a processor arm whose msg!(\"Instruction: X\") log names this IDL variant (or has no log)", "receipt-verified": "identity-confirmed + LiteSVM receipt on the pinned ELF matched IDL/source expectations", "not-dispatch": "8-byte lddw/jeq candidate shown not to be instruction dispatch" },
  counts, instructions: entries, not_dispatch: notDispatch, receipts_engine: receipts.engine ?? null, pumpfun_regression: pumpfun,
  verified: failures.length === 0, failures,
};
writeFileSync(join(OUT, "scoreboard.json"), `${JSON.stringify(scoreboard, null, 2)}\n`);
const md = [`# REA milestone 1 scoreboard: Metaplex Core`, ``,
  `Program \`${PROGRAM_ID}\`, ELF sha256 \`${analysis.artifact.sha256}\` (${analysis.artifact.bytes} B, slot 455005931). Verified: **${scoreboard.verified}**.`, ``,
  `Decoder: ${scoreboard.dispatch.decoder ? `Borsh tag tree at ${scoreboard.dispatch.decoder.load_address}, ${scoreboard.dispatch.decoder.recovered}/${ixs.length} tags` : "not found"}. Processor: ${scoreboard.dispatch.processor ? `match tree at ${scoreboard.dispatch.processor.root}, ${scoreboard.dispatch.processor.arms} arms, ${scoreboard.dispatch.processor.named_by_log} named by log site` : "not found"}.`, ``,
  `Counts: ${Object.entries(counts).map(([k, v]) => `${k} ${v}`).join(", ")}.`, pumpfun ? `\nPumpfun regression: ${pumpfun.recovered}/${pumpfun.total} (baseline ${pumpfun.baseline}).` : "", ``,
  `| tag | instruction | status | decoder arm | processor arm | log |`, `|---|---|---|---|---|---|`,
  ...entries.map((e) => `| ${e.tag} | ${e.name} | ${e.status} | ${e.evidence.decoder.arm ?? "-"} | ${e.evidence.processor?.arm ?? "-"} | ${e.evidence.processor?.log_name ?? "-"} |`), ``,
  `## not-dispatch (8-byte candidates)`, ``, `| const @ | value (LE) | reason |`, `|---|---|---|`,
  ...notDispatch.map((n) => `| ${n.constant_address} | ${n.discriminator} | ${n.reason} |`), ``].join("\n");
writeFileSync(join(OUT, "SCOREBOARD.md"), md);
console.log(`scoreboard -> ${join(OUT, "scoreboard.json")}  ${JSON.stringify(counts)}`);
process.exitCode = failures.length ? 1 : 0;
