import { describe, expect, it } from "vitest";
import { disassembleSbpf } from "./SbpfDisassembler.js";
import { scanSolanaTagDispatch } from "./SolanaTagDispatch.js";

const word = (opcode: number, dst: number, src: number, off: number, imm: number): number[] => {
  const b = new Uint8Array(8);
  const v = new DataView(b.buffer);
  b[0] = opcode; b[1] = (src << 4) | dst; v.setInt16(2, off, true); v.setInt32(4, imm, true);
  return [...b];
};
const LDXB = 0x71, JEQ = 0x15, JNE = 0x55, JSGT = 0x65, MOV = 0xb7, EXIT = 0x95;
const decode = (words: number[][]) => disassembleSbpf(new Uint8Array(words.flat()), 0, 0);

describe("scanSolanaTagDispatch", () => {
  it("recovers a balanced compare tree over a loaded tag byte", () => {
    // r1 = *(u8*)(r2+0); if r1 s> 2 goto HI; jeq 0 ->A; jeq 1 ->B; jne 2 ->ERR; C:...
    const words = [
      word(LDXB, 1, 2, 0, 0), // 0
      word(JSGT, 1, 0, 5, 2), // 1 -> 7
      word(JEQ, 1, 0, 8, 0), // 2 -> 11
      word(JEQ, 1, 0, 8, 1), // 3 -> 12
      word(JNE, 1, 0, 9, 2), // 4 -> 14 err
      word(MOV, 0, 0, 0, 2), // 5 tag 2 handler
      word(EXIT, 0, 0, 0, 0), // 6
      word(JEQ, 1, 0, 2, 3), // 7 -> 10
      word(JNE, 1, 0, 5, 4), // 8 -> 14 err
      word(MOV, 0, 0, 0, 4), // 9 tag 4
      word(MOV, 0, 0, 0, 3), // 10 tag 3
      word(MOV, 0, 0, 0, 0), // 11 tag 0
      word(MOV, 0, 0, 0, 1), // 12 tag 1
      word(EXIT, 0, 0, 0, 0), // 13
      word(MOV, 0, 0, 0, 99), // 14 err
      word(EXIT, 0, 0, 0, 0),
    ];
    const [tree, ...rest] = scanSolanaTagDispatch(decode(words));
    expect(rest).toHaveLength(0);
    expect(tree?.loadAddress).toBe(0);
    expect(tree?.handlers).toEqual([
      { tag: 0, target: 88 }, { tag: 1, target: 96 }, { tag: 2, target: 40 },
      { tag: 3, target: 80 }, { tag: 4, target: 72 },
    ]);
    expect(tree?.defaultTargets).toContain(112);
  });

  it("ignores byte loads with too few tag compares", () => {
    const words = [word(LDXB, 1, 2, 0, 0), word(JEQ, 1, 0, 1, 0), word(EXIT, 0, 0, 0, 0), word(EXIT, 0, 0, 0, 0)];
    expect(scanSolanaTagDispatch(decode(words))).toEqual([]);
  });
});
