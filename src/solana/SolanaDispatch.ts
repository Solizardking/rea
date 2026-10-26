import type { SbpfInstruction } from "./SbpfDisassembler.js";

/** One Anchor-style dispatch candidate recovered from the lddw/jeq idiom. */
export interface SolanaHandlerCandidate {
  readonly discriminator: string;
  readonly constantAddress: number;
  readonly constantFileOffset: number;
  readonly comparisonAddress: number;
  readonly branch: "jeq" | "jne";
  readonly branchTarget: number;
  readonly valueRegister: number;
  readonly constantRegister: number;
}

/** Instructions scanned after an lddw for its dispatch comparison. */
const COMPARISON_WINDOW = 8;

/** True when an instruction overwrites the given register. */
const writesRegister = (
  instruction: SbpfInstruction,
  register: number,
): boolean => {
  if (instruction.dst !== register) return false;
  if (instruction.mnemonic === "lddw") return true;
  const klass = instruction.opcode & 0x07;
  return klass === 0x01 || klass === 0x04 || klass === 0x07;
};

/** Render a 64-bit constant as Anchor discriminator bytes (little-endian hex). */
export const discriminatorHex = (imm64: bigint): string => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, imm64, true);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
};

/**
 * Recover dispatch candidates from the idiom Anchor/rustc emits for
 * instruction dispatch on sBPF: a 64-bit discriminator constant is loaded
 * with `lddw` and compared, register against register, by a nearby
 * `jeq`/`jne`. Candidates are reconstruction leads, not proof of a handler:
 * a constant survives only when the comparison actually consumes the loaded
 * register before anything overwrites it.
 */
export const scanSolanaDispatch = (
  instructions: readonly SbpfInstruction[],
): readonly SolanaHandlerCandidate[] => {
  const candidates: SolanaHandlerCandidate[] = [];
  const seen = new Set<string>();
  for (let index = 0; index < instructions.length; index += 1) {
    const load = instructions[index];
    if (load === undefined || load.mnemonic !== "lddw") continue;
    for (
      let ahead = index + 1;
      ahead <= Math.min(index + COMPARISON_WINDOW, instructions.length - 1);
      ahead += 1
    ) {
      const candidate = instructions[ahead];
      if (candidate === undefined) break;
      if (writesRegister(candidate, load.dst)) break;
      const isComparison =
        (candidate.mnemonic === "jeq" || candidate.mnemonic === "jne") &&
        candidate.srcIsRegister &&
        candidate.src === load.dst;
      if (!isComparison) continue;
      const discriminator = discriminatorHex(load.imm64);
      if (!seen.has(discriminator)) {
        seen.add(discriminator);
        candidates.push({
          discriminator,
          constantAddress: load.address,
          constantFileOffset: load.fileOffset,
          comparisonAddress: candidate.address,
          branch: candidate.mnemonic === "jne" ? "jne" : "jeq",
          branchTarget: candidate.address + 8 * (1 + candidate.offset),
          valueRegister: candidate.dst,
          constantRegister: load.dst,
        });
      }
      break;
    }
  }
  return candidates.sort((a, b) => a.constantAddress - b.constantAddress);
};
