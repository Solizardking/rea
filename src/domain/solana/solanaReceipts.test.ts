import { describe, expect, it } from "vitest";
import {
  bindSolanaReceipts,
  type SolanaReceiptsFile,
} from "./solanaReceipts.js";

const SHA = "a".repeat(64);
const receipt = (tag: number, kind: "positive" | "negative", pass = true) => ({
  tag,
  instruction: `Ix${String(tag)}`,
  kind,
  expectation: "x",
  pass,
  tx_ok: kind === "positive",
  err: null,
  compute_units: 1,
});
const file = (over: Partial<SolanaReceiptsFile> = {}): SolanaReceiptsFile => ({
  schema: "rea.solana-receipts/v1",
  engine: { name: "litesvm", version: "1.6.1", network: "none" },
  program_id: "CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d",
  artifact_sha256: SHA,
  receipts: [
    receipt(0, "positive"),
    receipt(1, "positive"),
    receipt(1, "negative", false),
    receipt(2, "negative"),
  ],
  ...over,
});
const art = { path: "/a.so", sha256: SHA, bytes: 1 };
const rf = { path: "/r.json", sha256: "b".repeat(64) };

describe("bindSolanaReceipts", () => {
  it("promotes only bound, passing positive claims", () => {
    const r = bindSolanaReceipts(art, file(), rf);
    expect(r.binding).toBe("bound");
    expect(r.claims.map((c) => c.status)).toEqual([
      "receipt-verified",
      "lead",
      "lead",
    ]);
    expect(r.claims[1]?.reason).toMatch(/failed/);
    expect(r.claims[2]?.reason).toMatch(/negative controls only/);
    expect(r.counts).toEqual({ receipt_verified: 1, lead: 2, receipts: 4 });
  });
  it("downgrades everything on artifact hash mismatch", () => {
    const r = bindSolanaReceipts(
      { ...art, sha256: "c".repeat(64) },
      file(),
      rf,
    );
    expect(r.binding).toBe("artifact-mismatch");
    expect(r.counts.receipt_verified).toBe(0);
  });
  it("downgrades unsupported or networked engines", () => {
    expect(
      bindSolanaReceipts(
        art,
        file({ engine: { name: "mainnet", version: "1", network: "none" } }),
        rf,
      ).binding,
    ).toBe("unsupported-engine");
    const n = bindSolanaReceipts(
      art,
      file({ engine: { name: "litesvm", version: "1", network: "devnet" } }),
      rf,
    );
    expect(n.binding).toBe("networked-engine");
    expect(n.counts.receipt_verified).toBe(0);
  });
});
