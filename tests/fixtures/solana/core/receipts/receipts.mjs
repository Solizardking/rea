// Offline differential receipts for Metaplex Core on LiteSVM (no network).
// Loads the pinned ELF and checks observed behavior against IDL/source expectations.
import { LiteSVM } from "litesvm";
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import {
  address, generateKeyPairSigner, pipe, createTransactionMessage, setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash, appendTransactionMessageInstruction,
  signTransactionMessageWithSigners, lamports, AccountRole, getAddressEncoder,
} from "@solana/kit";

const ELF = process.argv[2] ?? new URL("../core.so", import.meta.url).pathname;
const OUT = process.argv[3] ?? new URL("./receipts.json", import.meta.url).pathname;
const PIN = "51d41542456639a01820c747e72b9d3b4ca258930a5bbb7e78db0cda133dc209";
const bytes = readFileSync(ELF);
const sha = createHash("sha256").update(bytes).digest("hex");
if (sha !== PIN) throw new Error(`pinned ELF mismatch ${sha}`);
const CORE = address("CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d");
const SYS = address("11111111111111111111111111111111");
const enc = getAddressEncoder();
const svm = new LiteSVM();
svm.addProgram(CORE, new Uint8Array(bytes));

const str = (s) => { const b = Buffer.from(s); const l = Buffer.alloc(4); l.writeUInt32LE(b.length); return Buffer.concat([l, b]); };
const meta = (a, role) => ({ address: a, role });
const W = AccountRole.WRITABLE, R = AccountRole.READONLY, WS = AccountRole.WRITABLE_SIGNER, RS = AccountRole.READONLY_SIGNER;
const NONE = meta(CORE, R); // Shank optional-account placeholder

const payer = await generateKeyPairSigner();
svm.airdrop(payer.address, lamports(10_000_000_000n));
const send = async (accounts, data, signers = []) => {
  const ix = { programAddress: CORE, accounts, data: new Uint8Array(data) };
  const msg = pipe(createTransactionMessage({ version: 0 }), (m) => setTransactionMessageFeePayerSigner(payer, m),
    (m) => setTransactionMessageLifetimeUsingBlockhash({ blockhash: svm.latestBlockhash(), lastValidBlockHeight: 0n }, m),
    (m) => appendTransactionMessageInstruction({ ...ix, accounts: accounts.map((a) => signers.find((s) => s.address === a.address) ? { ...a, signer: signers.find((s) => s.address === a.address) } : a) }, m));
  const tx = await signTransactionMessageWithSigners(msg);
  const res = svm.sendTransaction(tx);
  svm.expireBlockhash();
  const failed = typeof res.err === "function";
  const m = failed ? res.meta() : res;
  return { ok: !failed, err: failed ? String(res.err()) : null, logs: m.logs(), cu: Number(m.computeUnitsConsumed()) };
};
const acct = (a) => { const x = svm.getAccount(a); return x.exists ? x : null; };
const receipts = [];
const record = (tag, name, expectation, r, pass, observed) => receipts.push({ tag, name, expectation, pass, observed, tx_ok: r.ok, err: r.err, compute_units: r.cu, logs: r.logs });

// tag 1 CreateCollectionV1
const col = await generateKeyPairSigner();
let r = await send([meta(col.address, WS), NONE, meta(payer.address, WS), meta(SYS, R)], [1, ...str("Col"), ...str("https://x/c"), 0], [col]);
let a = acct(col.address);
record(1, "CreateCollectionV1", "collection account owned by Core, data[0]=Key::CollectionV1(5), update_authority=payer", r,
  r.ok && a?.programAddress === CORE && a.data[0] === 5 && Buffer.from(a.data.slice(1, 33)).equals(Buffer.from(enc.encode(payer.address))),
  a ? { owner: a.programAddress, key: a.data[0], len: a.data.length } : null);

// tag 0 CreateV1
const asset = await generateKeyPairSigner();
r = await send([meta(asset.address, WS), NONE, NONE, meta(payer.address, WS), NONE, NONE, meta(SYS, R), NONE], [0, 0, ...str("A"), ...str("https://x/a"), 0], [asset]);
a = acct(asset.address);
record(0, "CreateV1", "asset owned by Core, data[0]=Key::AssetV1(1), owner=payer", r,
  r.ok && a?.programAddress === CORE && a.data[0] === 1 && Buffer.from(a.data.slice(1, 33)).equals(Buffer.from(enc.encode(payer.address))),
  a ? { owner: a.programAddress, key: a.data[0], len: a.data.length } : null);

// tag 14 TransferV1
const newOwner = await generateKeyPairSigner();
r = await send([meta(asset.address, W), NONE, meta(payer.address, WS), NONE, meta(newOwner.address, R), NONE, NONE], [14, 0]);
a = acct(asset.address);
record(14, "TransferV1", "asset owner field (bytes 1..33) becomes newOwner", r,
  r.ok && a && Buffer.from(a.data.slice(1, 33)).equals(Buffer.from(enc.encode(newOwner.address))), a ? { key: a.data[0] } : null);

// tag 14 negative: old owner can no longer transfer
r = await send([meta(asset.address, W), NONE, meta(payer.address, WS), NONE, meta(payer.address, R), NONE, NONE], [14, 0]);
record(14, "TransferV1 (non-owner, negative)", "rejected: payer is no longer owner", r, !r.ok, null);

// tag 12 BurnV1 by new owner
svm.airdrop(newOwner.address, lamports(1_000_000_000n));
r = await send([meta(asset.address, W), NONE, meta(payer.address, WS), meta(newOwner.address, RS), NONE, NONE], [12, 0], [newOwner]);
a = acct(asset.address);
record(12, "BurnV1", "asset reduced to tombstone (Key::Uninitialized, 1 byte) or closed", r,
  r.ok && (a === null || (a.data.length <= 1 && (a.data[0] ?? 0) === 0)), a ? { key: a.data[0], len: a.data.length } : "closed");

// tag 42 out of range -> default arm (invalid instruction)
r = await send([meta(payer.address, WS)], [42]);
record(42, "out-of-range tag (negative)", "rejected via dispatch default arm", r, !r.ok, null);

const out = { engine: "litesvm@1.6.1", network: "none", program_id: CORE, elf_sha256: sha, generated_by: "receipts.mjs", receipts };
writeFileSync(OUT, JSON.stringify(out, null, 2) + "\n");
for (const x of receipts) console.log(x.pass ? "PASS" : "FAIL", x.tag, x.name, x.err ?? "", x.compute_units);
process.exitCode = receipts.every((x) => x.pass) ? 0 : 1;
