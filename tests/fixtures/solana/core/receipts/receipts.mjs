// Offline differential receipts for Metaplex Core on LiteSVM (no network).
// Loads the pinned ELF and checks observed behavior against IDL/source expectations.
// Output: rea.solana-receipts/v1 JSON consumed by `rea solana-receipts`.
import { LiteSVM } from "litesvm";
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import {
  address, generateKeyPairSigner, pipe, createTransactionMessage, setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash, appendTransactionMessageInstruction,
  signTransactionMessageWithSigners, lamports, AccountRole, getAddressEncoder, getProgramDerivedAddress,
} from "@solana/kit";

const ELF = process.argv[2] ?? new URL("../core.so", import.meta.url).pathname;
const OUT = process.argv[3] ?? new URL("./receipts.json", import.meta.url).pathname;
const bytes = readFileSync(ELF);
const sha = createHash("sha256").update(bytes).digest("hex");
const CORE = address("CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d");
const SYS = address("11111111111111111111111111111111");
const enc = getAddressEncoder();
const svm = new LiteSVM();
svm.addProgram(CORE, new Uint8Array(bytes));

const str = (s) => { const b = Buffer.from(s); const l = Buffer.alloc(4); l.writeUInt32LE(b.length); return [...l, ...b]; };
const some = (xs) => [1, ...xs];
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return [...b]; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return [...b]; };
const pk = (a) => [...enc.encode(a)];
const W = AccountRole.WRITABLE, R = AccountRole.READONLY, WS = AccountRole.WRITABLE_SIGNER, RS = AccountRole.READONLY_SIGNER;
const m = (a, role) => ({ address: a, role });
const NONE = m(CORE, R); // Shank optional-account placeholder
const has = (buf, needle) => Buffer.from(buf).indexOf(Buffer.from(needle)) >= 0;

const payer = await generateKeyPairSigner();
svm.airdrop(payer.address, lamports(100_000_000_000n));
const send = async (accounts, data, signers = []) => {
  const withSigners = accounts.map((a) => { const s = signers.find((x) => x.address === a.address); return s ? { ...a, signer: s } : a; });
  const msg = pipe(createTransactionMessage({ version: 0 }), (x) => setTransactionMessageFeePayerSigner(payer, x),
    (x) => setTransactionMessageLifetimeUsingBlockhash({ blockhash: svm.latestBlockhash(), lastValidBlockHeight: 0n }, x),
    (x) => appendTransactionMessageInstruction({ programAddress: CORE, accounts: withSigners, data: new Uint8Array(data) }, x));
  const res = svm.sendTransaction(await signTransactionMessageWithSigners(msg));
  svm.expireBlockhash();
  const failed = typeof res.err === "function";
  const meta = failed ? res.meta() : res;
  return { ok: !failed, err: failed ? String(res.err()) : null, logs: meta.logs(), cu: Number(meta.computeUnitsConsumed()) };
};
const data = (a) => { const x = svm.getAccount(a); return x.exists ? Buffer.from(x.data) : null; };
const receipts = [];
const receipt = (tag, name, expectation, r, pass, kind = "positive") => {
  receipts.push({ tag, instruction: name, kind, expectation, pass: Boolean(pass), tx_ok: r.ok, err: r.err, compute_units: r.cu, log_instruction: (r.logs.find((l) => l.includes("Instruction: ")) ?? "").replace("Program log: Instruction: ", "") || null });
};
const P = m(payer.address, WS);

// ---- collection lifecycle ----
const col = await generateKeyPairSigner();
let r = await send([m(col.address, WS), NONE, P, m(SYS, R)], [1, ...str("Col"), ...str("https://x/c"), 0], [col]);
receipt(1, "CreateCollectionV1", "Key::CollectionV1(5), update_authority=payer", r, r.ok && data(col.address)?.[0] === 5 && data(col.address).subarray(1, 33).equals(Buffer.from(pk(payer.address))));
r = await send([m(col.address, W), P, NONE, NONE, m(SYS, R), NONE], [16, ...some(str("Renamed")), 0]);
receipt(16, "UpdateCollectionV1", "collection name becomes 'Renamed'", r, r.ok && has(data(col.address), "Renamed"));
// Attributes plugin (Plugin::Attributes=6, empty list)
let before = data(col.address).length;
r = await send([m(col.address, W), P, NONE, m(SYS, R), NONE], [3, 6, ...u32(0), 0]);
receipt(3, "AddCollectionPluginV1", "collection grows (plugin header + registry + Attributes)", r, r.ok && data(col.address).length > before);
r = await send([m(col.address, W), P, NONE, m(SYS, R), NONE], [7, 6, ...u32(1), ...str("k1"), ...str("v1")]);
receipt(7, "UpdateCollectionPluginV1", "collection Attributes contains k1=v1", r, r.ok && has(data(col.address), "k1") && has(data(col.address), "v1"));
const delegate = await generateKeyPairSigner();
r = await send([m(col.address, W), P, NONE, m(SYS, R), NONE], [9, 6, 3, ...pk(delegate.address)]);
receipt(9, "ApproveCollectionPluginAuthorityV1", "Attributes authority = Address(delegate)", r, r.ok && has(data(col.address), pk(delegate.address)));
r = await send([m(col.address, W), P, NONE, m(SYS, R), NONE], [11, 6]);
receipt(11, "RevokeCollectionPluginAuthorityV1", "delegate pubkey removed from collection", r, r.ok && !has(data(col.address), pk(delegate.address)));
const withPlugin = data(col.address).length;
r = await send([m(col.address, W), P, NONE, m(SYS, R), NONE], [5, 6]);
receipt(5, "RemoveCollectionPluginV1", "Attributes plugin removed (k1 gone, account shrinks)", r, r.ok && data(col.address).length < withPlugin && !has(data(col.address), "k1"));

// ---- asset lifecycle ----
const asset = await generateKeyPairSigner();
r = await send([m(asset.address, WS), NONE, NONE, P, NONE, NONE, m(SYS, R), NONE], [0, 0, ...str("A"), ...str("https://x/a"), 0], [asset]);
receipt(0, "CreateV1", "Key::AssetV1(1), owner=payer", r, r.ok && data(asset.address)?.[0] === 1 && data(asset.address).subarray(1, 33).equals(Buffer.from(pk(payer.address))));
r = await send([m(asset.address, W), NONE, P, NONE, m(SYS, R), NONE], [15, ...some(str("Renamed")), 0, 0]);
receipt(15, "UpdateV1", "asset name becomes 'Renamed'", r, r.ok && has(data(asset.address), "Renamed"));
r = await send([m(asset.address, W), NONE, P, NONE, NONE, m(SYS, R), NONE], [30, ...some(str("RenamedV2")), 0, 0]);
receipt(30, "UpdateV2", "asset name becomes 'RenamedV2'", r, r.ok && has(data(asset.address), "RenamedV2"));
before = data(asset.address).length;
r = await send([m(asset.address, W), NONE, P, NONE, m(SYS, R), NONE], [2, 1, 0, 0]); // FreezeDelegate{frozen:false}, default authority (Owner)
receipt(2, "AddPluginV1", "asset grows; FreezeDelegate attached", r, r.ok && data(asset.address).length > before);
const other = await generateKeyPairSigner();
r = await send([m(asset.address, W), NONE, P, NONE, m(SYS, R), NONE], [8, 1, 3, ...pk(delegate.address)]);
receipt(8, "ApprovePluginAuthorityV1", "FreezeDelegate authority = Address(delegate)", r, r.ok && has(data(asset.address), pk(delegate.address)));
r = await send([m(asset.address, W), NONE, P, m(delegate.address, RS), m(SYS, R), NONE], [6, 1, 1], [delegate]); // delegate freezes
receipt(6, "UpdatePluginV1", "delegate sets frozen=true", r, r.ok);
r = await send([m(asset.address, W), NONE, P, NONE, m(other.address, R), NONE, NONE], [14, 0]);
receipt(14, "TransferV1 (frozen, negative)", "owner transfer rejected while frozen", r, !r.ok, "negative");
r = await send([m(asset.address, W), NONE, P, m(delegate.address, RS), m(SYS, R), NONE], [6, 1, 0], [delegate]); // unfreeze
receipt(6, "UpdatePluginV1 (unfreeze)", "delegate sets frozen=false", r, r.ok);
r = await send([m(asset.address, W), NONE, P, NONE, m(SYS, R), NONE], [10, 1]);
receipt(10, "RevokePluginAuthorityV1", "delegate pubkey removed from asset", r, r.ok && !has(data(asset.address), pk(delegate.address)));
const withAssetPlugin = data(asset.address).length;
r = await send([m(asset.address, W), NONE, P, NONE, m(SYS, R), NONE], [4, 1]);
receipt(4, "RemovePluginV1", "asset shrinks (plugin removed)", r, r.ok && data(asset.address).length < withAssetPlugin);
r = await send([m(asset.address, W), NONE, P, NONE, m(other.address, R), NONE, NONE], [14, 0]);
receipt(14, "TransferV1", "owner field becomes other", r, r.ok && data(asset.address).subarray(1, 33).equals(Buffer.from(pk(other.address))));
r = await send([m(asset.address, W), NONE, P, NONE, m(payer.address, R), NONE, NONE], [14, 0]);
receipt(14, "TransferV1 (non-owner, negative)", "rejected: NoApprovals(26)", r, !r.ok && /code: 26\b/.test(r.err), "negative");

// ---- Execute: asset-signer PDA CPIs a system transfer ----
const [assetSigner] = await getProgramDerivedAddress({ programAddress: CORE, seeds: [Buffer.from("mpl-core-execute"), Buffer.from(pk(asset.address))] });
svm.airdrop(assetSigner, lamports(2_000_000_000n));
svm.airdrop(other.address, lamports(1_000_000_000n));
const recipient = await generateKeyPairSigner();
const inner = [...u32(2), ...u64(123456789)];
r = await send([m(asset.address, W), NONE, m(assetSigner, W), P, m(other.address, RS), m(SYS, R), m(SYS, R), m(assetSigner, W), m(recipient.address, W)], [31, ...u32(inner.length), ...inner], [other]);
const got = svm.getAccount(recipient.address);
receipt(31, "ExecuteV1", "asset-signer PDA transfers 123456789 lamports via system CPI", r, r.ok && got.exists && got.lamports === 123456789n);

// CompressV1/DecompressV1/Collect: no receipt (needs log-wrapper/merkle proof or hard-coded fee recipients).

// ---- burn ----
r = await send([m(asset.address, W), NONE, P, m(other.address, RS), NONE, NONE], [12, 0], [other]);
receipt(12, "BurnV1", "asset reduced to tombstone or closed", r, r.ok && (data(asset.address) === null || data(asset.address).length <= 1));

// ---- V2 creators ----
const col2 = await generateKeyPairSigner();
r = await send([m(col2.address, WS), NONE, P, m(SYS, R)], [21, ...str("Col2"), ...str("u"), 0, 0], [col2]);
receipt(21, "CreateCollectionV2", "Key::CollectionV1(5)", r, r.ok && data(col2.address)?.[0] === 5);
const a2 = await generateKeyPairSigner();
r = await send([m(a2.address, WS), m(col2.address, W), NONE, P, NONE, NONE, m(SYS, R), NONE], [20, 0, ...str("A2"), ...str("u"), 0, 0], [a2]);
receipt(20, "CreateV2", "Key::AssetV1(1), update authority = Collection(col2)", r, r.ok && data(a2.address)?.[0] === 1 && has(data(a2.address), pk(col2.address)));
// BurnCollectionV1 on an empty collection
r = await send([m(col.address, W), P, NONE, NONE], [13, 0]);
receipt(13, "BurnCollectionV1", "empty collection reduced to tombstone or closed", r, r.ok && (data(col.address) === null || data(col.address).length <= 1));

// ---- groups ----
const group = await generateKeyPairSigner();
r = await send([m(group.address, WS), NONE, P, m(SYS, R)], [39, ...str("G"), ...str("u"), ...u32(0)], [group]);
receipt(39, "CreateGroupV1", "Key::GroupV1(6) account created", r, r.ok && data(group.address)?.[0] === 6);
r = await send([m(group.address, W), P, NONE, NONE, m(SYS, R)], [41, ...some(str("GRenamed")), 0]);
receipt(41, "UpdateGroupV1", "group name becomes 'GRenamed'", r, r.ok && has(data(group.address), "GRenamed"));
r = await send([m(group.address, W), P, NONE, m(SYS, R), m(col2.address, W)], [33]);
receipt(33, "AddCollectionsToGroupV1", "group records col2", r, r.ok && has(data(group.address), pk(col2.address)));
r = await send([m(group.address, W), P, NONE, m(SYS, R), m(col2.address, W)], [34, ...u32(1), ...pk(col2.address)]);
receipt(34, "RemoveCollectionsFromGroupV1", "col2 removed from group", r, r.ok && !has(data(group.address), pk(col2.address)));
const a3 = await generateKeyPairSigner();
await send([m(a3.address, WS), NONE, NONE, P, NONE, NONE, m(SYS, R), NONE], [0, 0, ...str("A3"), ...str("u"), 0], [a3]);
r = await send([m(group.address, W), P, NONE, m(SYS, R), m(a3.address, W)], [35]);
receipt(35, "AddAssetsToGroupV1", "group records a3", r, r.ok && has(data(group.address), pk(a3.address)));
r = await send([m(group.address, W), P, NONE, m(SYS, R), m(a3.address, W)], [36, ...u32(1), ...pk(a3.address)]);
receipt(36, "RemoveAssetsFromGroupV1", "a3 removed from group", r, r.ok && !has(data(group.address), pk(a3.address)));
const child = await generateKeyPairSigner();
await send([m(child.address, WS), NONE, P, m(SYS, R)], [39, ...str("C"), ...str("u"), ...u32(0)], [child]);
r = await send([m(group.address, W), P, NONE, m(SYS, R), m(child.address, W)], [37, ...u32(1), ...pk(child.address)]);
receipt(37, "AddGroupsToGroupV1", "parent records child group", r, r.ok && has(data(group.address), pk(child.address)));
r = await send([m(group.address, W), P, NONE, m(SYS, R), m(child.address, W)], [38, ...u32(1), ...pk(child.address)]);
receipt(38, "RemoveGroupsFromGroupV1", "child removed from parent", r, r.ok && !has(data(group.address), pk(child.address)));
r = await send([m(child.address, W), P, NONE], [40]);
receipt(40, "CloseGroupV1", "empty group closed", r, r.ok && (data(child.address) === null || data(child.address).length <= 1));

// ---- dispatch boundary ----
r = await send([P], [42]);
receipt(42, "out-of-range tag", "rejected in Borsh decode (default arm)", r, !r.ok, "negative");

const out = { schema: "rea.solana-receipts/v1", engine: { name: "litesvm", version: "1.6.1", network: "none" }, program_id: CORE, artifact_sha256: sha, receipts };
writeFileSync(OUT, JSON.stringify(out, null, 2) + "\n");
for (const x of receipts) console.log(x.pass ? "PASS" : "FAIL", x.tag, x.instruction, x.err ?? "", x.compute_units, x.log_instruction ?? "");
