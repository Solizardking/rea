import { describe, expect, it } from "vitest";
import { parseExecutableHeader } from "./binaryTarget.js";

const solanaProgramHeader = (machine: number, type = 3): Buffer => {
  const bytes = Buffer.alloc(64);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  bytes.writeUInt16LE(type, 16);
  bytes.writeUInt16LE(machine, 18);
  bytes.writeUInt32LE(1, 20);
  bytes.writeUInt16LE(64, 52);
  return bytes;
};

describe("Solana sBPF ELF header recognition", () => {
  it.each([
    [263, "EM_SBF"],
    [247, "EM_BPF"],
  ] as const)(
    "classifies e_machine %s (%s) as sbpf without further ELF metadata",
    (machine, _name) => {
      const parsed = parseExecutableHeader(solanaProgramHeader(machine), "x64");
      if (!parsed.ok) throw new Error(parsed.error);
      expect(parsed.value).toEqual({
        format: "elf",
        architecture: "sbpf",
        availableArchitectures: ["sbpf"],
      });
    },
  );

  it("keeps rejecting e_machine values with no classified family", () => {
    const parsed = parseExecutableHeader(solanaProgramHeader(0x1234), "x64");
    expect(parsed).toEqual({
      ok: false,
      error: "unsupported ELF architecture",
    });
  });
});
