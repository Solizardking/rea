import type { SbpfInstruction } from "./SbpfDisassembler.js";

/** One leaf of a 1-byte instruction-tag dispatch tree (Shank/Borsh enum). */
export interface SolanaTagHandler {
  readonly tag: number;
  readonly target: number;
}

/** A recovered 1-byte tag dispatch: `ldxb` of instruction data then a
 * compare tree (`jeq`/`jne`/`jgt`/`jsgt`/... against immediates). */
export interface SolanaTagDispatch {
  readonly loadAddress: number;
  readonly tagRegister: number;
  readonly loadBaseRegister: number;
  readonly loadOffset: number;
  readonly compareCount: number;
  readonly handlers: readonly SolanaTagHandler[];
  /** Targets reached by multi-value ranges (typically the invalid-tag error). */
  readonly defaultTargets: readonly number[];
}

const COMPARE = new Set([
  "jeq", "jne", "jgt", "jge", "jlt", "jle", "jsgt", "jsge", "jslt", "jsle",
]);
const MIN_HANDLERS = 4;
const SEARCH_WINDOW = 12;
const MAX_NODES = 4096;

const isByteLoad = (i: SbpfInstruction): boolean =>
  (i.opcode & 0x07) === 0x01 && ((i.opcode >> 3) & 0x03) === 2;

export const writesRegister = (i: SbpfInstruction, reg: number): boolean => {
  if (i.dst !== reg) return false;
  if (i.mnemonic === "lddw") return true;
  const k = i.opcode & 0x07;
  return k === 0x01 || k === 0x04 || k === 0x07;
};

type Range = readonly [number, number];
const clip = (lo: number, hi: number): Range | undefined =>
  lo <= hi ? [lo, hi] : undefined;

/** Walk a compare tree on `reg` starting at instruction index `start`. */
const walkTree = (
  instructions: readonly SbpfInstruction[],
  byAddress: ReadonlyMap<number, number>,
  start: number,
  reg: number,
): { handlers: Map<number, number>; defaults: Set<number>; compares: number } => {
  const handlers = new Map<number, number>();
  const defaults = new Set<number>();
  const visitedCompares = new Set<number>();
  const stack: [number, Range][] = [[start, [0, 255]]];
  let nodes = 0;
  while (stack.length > 0 && nodes < MAX_NODES) {
    nodes += 1;
    const [index, range] = stack.pop() as [number, Range];
    const ins = instructions[index];
    if (ins === undefined) continue;
    const comparesTag = COMPARE.has(ins.mnemonic) && !ins.srcIsRegister && ins.dst === reg;
    if (range[0] === range[1] && !comparesTag) {
      if (!handlers.has(range[0])) handlers.set(range[0], ins.address);
      continue;
    }
    if (ins.mnemonic === "ja") {
      const t = byAddress.get(ins.address + 8 * (1 + ins.offset));
      if (t !== undefined && t > index) stack.push([t, range]);
      continue;
    }
    const isCmp = comparesTag;
    if (!isCmp) {
      // A multi-value range leaving the tree: the invalid-tag / default arm.
      defaults.add(ins.address);
      continue;
    }
    visitedCompares.add(ins.address);
    const target = byAddress.get(ins.address + 8 * (1 + ins.offset));
    const [lo, hi] = range;
    const lower = (a: number, b: number): Range | undefined => clip(Math.max(lo, a), Math.min(hi, b));
    const imm = ins.imm;
    let taken: (Range | undefined)[];
    let fall: (Range | undefined)[];
    switch (ins.mnemonic) {
      case "jeq": taken = [lower(imm, imm)]; fall = [lower(0, imm - 1), lower(imm + 1, 255)]; break;
      case "jne": fall = [lower(imm, imm)]; taken = [lower(0, imm - 1), lower(imm + 1, 255)]; break;
      case "jgt": case "jsgt": taken = [lower(imm + 1, 255)]; fall = [lower(0, imm)]; break;
      case "jge": case "jsge": taken = [lower(imm, 255)]; fall = [lower(0, imm - 1)]; break;
      case "jlt": case "jslt": taken = [lower(0, imm - 1)]; fall = [lower(imm, 255)]; break;
      default: taken = [lower(0, imm)]; fall = [lower(imm + 1, 255)]; break;
    }
    for (const r of fall) if (r) stack.push([index + 1, r]);
    if (target !== undefined && target > index)
      for (const r of taken) if (r) stack.push([target, r]);
  }
  return { handlers, defaults, compares: visitedCompares.size };
};

/**
 * Recover 1-byte tag dispatch trees, the shape rustc emits on sBPF for a
 * `match` over a Borsh enum discriminant (Shank/native programs). LLVM's BPF
 * backend lowers such switches to a balanced compare tree rather than a
 * jump table. Each result is a reconstruction lead.
 */
export const scanSolanaTagDispatch = (
  instructions: readonly SbpfInstruction[],
): readonly SolanaTagDispatch[] => {
  const byAddress = new Map<number, number>();
  instructions.forEach((ins, i) => byAddress.set(ins.address, i));
  const results: SolanaTagDispatch[] = [];
  for (let i = 0; i < instructions.length; i += 1) {
    const load = instructions[i];
    if (load === undefined || !isByteLoad(load)) continue;
    let first = -1;
    for (let j = i + 1; j <= Math.min(i + SEARCH_WINDOW, instructions.length - 1); j += 1) {
      const ins = instructions[j];
      if (ins === undefined) break;
      if (COMPARE.has(ins.mnemonic) && !ins.srcIsRegister && ins.dst === load.dst) { first = j; break; }
      if (writesRegister(ins, load.dst) || (ins.opcode & 0x07) === 0x05) break;
    }
    if (first < 0) continue;
    const { handlers, defaults, compares } = walkTree(instructions, byAddress, first, load.dst);
    if (handlers.size < MIN_HANDLERS) continue;
    results.push({
      loadAddress: load.address,
      tagRegister: load.dst,
      loadBaseRegister: load.src,
      loadOffset: load.offset,
      compareCount: compares,
      handlers: [...handlers].map(([tag, target]) => ({ tag, target })).sort((a, b) => a.tag - b.tag),
      defaultTargets: [...defaults].sort((a, b) => a - b),
    });
  }
  return results.sort((a, b) => b.handlers.length - a.handlers.length || a.loadAddress - b.loadAddress);
};
