import { mkdtemp, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SolanaReceiptsService } from "./SolanaReceiptsService.js";

describe("SolanaReceiptsService", () => {
  it("emits artifact-bound Evidence and rejects malformed receipts", async () => {
    const dir = await mkdtemp(join(tmpdir(), "rea-rcpt-"));
    const elf = Buffer.from("\x7fELF-fake");
    await writeFile(join(dir, "p.so"), elf);
    const sha = createHash("sha256").update(elf).digest("hex");
    await writeFile(
      join(dir, "r.json"),
      JSON.stringify({
        schema: "rea.solana-receipts/v1",
        engine: { name: "litesvm", version: "1.6.1", network: "none" },
        program_id: "CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d",
        artifact_sha256: sha,
        receipts: [
          {
            tag: 0,
            instruction: "CreateV1",
            kind: "positive",
            expectation: "x",
            pass: true,
            tx_ok: true,
            err: null,
            compute_units: 5,
          },
        ],
      }),
    );
    await writeFile(join(dir, "bad.json"), "{}");
    const service = new SolanaReceiptsService();
    const ok = await service.inspect({
      path: join(dir, "p.so"),
      receipts_path: join(dir, "r.json"),
    });
    expect(ok.ok).toBe(true);
    if (ok.ok) {
      expect(ok.value.subject?.digest.sha256).toContain(sha);
      expect(
        (ok.value.normalized_result as { counts: { receipt_verified: number } })
          .counts.receipt_verified,
      ).toBe(1);
    }
    const bad = await service.inspect({
      path: join(dir, "p.so"),
      receipts_path: join(dir, "bad.json"),
    });
    expect(bad.ok).toBe(false);
  });
});
