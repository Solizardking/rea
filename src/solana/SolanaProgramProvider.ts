import { createHash } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type { SolanaProgramPort } from "../application/solana/SolanaProgramPort.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";
import type {
  AnalyzeSolanaProgramInput,
  SolanaProgramAnalysis,
} from "../domain/solana/solanaProgram.js";
import {
  parseSolanaElf,
  solanaElfMachineName,
  solanaTextSection,
  SolanaElfFailure,
  ELF_MACHINE_BPF,
  type SolanaElfImage,
} from "./SolanaElf.js";
import {
  disassembleSbpf,
  isUnknownSbpfInstruction,
} from "./SbpfDisassembler.js";
import { scanSolanaDispatch } from "./SolanaDispatch.js";
import { scanSolanaTagDispatch } from "./SolanaTagDispatch.js";
import {
  DEFAULT_SOLANA_RPC_URL,
  fetchSolanaProgramElf,
  SolanaRpcFailure,
} from "./SolanaRpc.js";

/** Bundled analyzer identity; on-chain facts are separate observed values. */
export const SOLANA_PROGRAM_PROVIDER_IDENTITY = {
  id: "solana-sbpf",
  name: "REA Solana sBPF program analyzer",
  version: "1",
} as const;

const OPERATION = "analyze_solana_program";
/** Solana program accounts are bounded well below this fixed intake allowance. */
const MAX_ELF_BYTES = 64 * 1024 * 1024;
const MAX_RELEVANT_STRINGS = 64;
const RELEVANT_STRING = /sol_|invoke|syscall|cpi/i;

const BASE_LIMITATIONS: readonly string[] = [
  "Handler candidates come only from the lddw-constant dispatch-comparison idiom Anchor/rustc emits; table dispatch, split 32-bit compares, and computed jumps are not recovered.",
  "Disassembly is a linear sweep by the bundled sBPF decoder, not a Ghidra/IDA-grade lift: no Rust source, types, control-flow recovery, or account layouts are produced.",
  "Discriminator candidates are reconstruction leads, never proof of behavior; parity with a deployed program is established only by differential tests against the captured original.",
];

interface AcquiredProgram {
  readonly bytes: Uint8Array;
  readonly path: string;
  readonly source: "local-file" | "solana-rpc";
  readonly programId: string | null;
  readonly programDataAccount: string | null;
  readonly slot: number | null;
}

const readLocalElf = async (
  path: string,
  signal: AbortSignal | undefined,
): Promise<Result<AcquiredProgram, AnalysisError>> => {
  let info: Awaited<ReturnType<typeof stat>>;
  try {
    info = await stat(path);
  } catch (cause) {
    const code = (cause as NodeJS.ErrnoException).code;
    if (code === "EACCES" || code === "EPERM")
      return err(
        new AnalysisAccessDeniedError(OPERATION, path, code, { cause }),
      );
    if (
      code === "ENOENT" ||
      code === "ENOTDIR" ||
      code === "ELOOP" ||
      code === "ENAMETOOLONG"
    )
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_value",
            message: `Selected ELF file cannot be resolved: ${path} (${code}).`,
          },
        ]),
      );
    return err(
      new ProviderAdapterError(SOLANA_PROGRAM_PROVIDER_IDENTITY.id, OPERATION, {
        cause,
      }),
    );
  }
  if (!info.isFile())
    return err(
      new AnalysisInputError(OPERATION, undefined, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected path is not a regular file: ${path}.`,
        },
      ]),
    );
  if (info.size > MAX_ELF_BYTES)
    return err(
      new AnalysisResourceConstraintError(
        OPERATION,
        "memory",
        `Selected ELF ${path} is ${String(info.size)} bytes, above the ${String(MAX_ELF_BYTES)}-byte intake allowance.`,
        { maximum_bytes: MAX_ELF_BYTES },
      ),
    );
  try {
    const bytes = await readFile(path, { signal });
    return ok({
      bytes,
      path,
      source: "local-file",
      programId: null,
      programDataAccount: null,
      slot: null,
    });
  } catch (cause) {
    return err(
      new ProviderAdapterError(SOLANA_PROGRAM_PROVIDER_IDENTITY.id, OPERATION, {
        cause,
      }),
    );
  }
};

const fetchProgramElf = async (
  input: AnalyzeSolanaProgramInput,
  rpcUrl: string,
  signal: AbortSignal | undefined,
): Promise<Result<AcquiredProgram, AnalysisError>> => {
  const programId = input.program_id as string;
  const outDir = input.out_dir as string;
  let fetched: Awaited<ReturnType<typeof fetchSolanaProgramElf>>;
  try {
    fetched = await fetchSolanaProgramElf(
      programId,
      rpcUrl,
      signal === undefined ? {} : { signal },
    );
  } catch (cause) {
    if (cause instanceof SolanaRpcFailure)
      return err(
        new ProviderAdapterError(
          SOLANA_PROGRAM_PROVIDER_IDENTITY.id,
          OPERATION,
          { cause },
        ),
      );
    return err(
      new ProviderAdapterError(SOLANA_PROGRAM_PROVIDER_IDENTITY.id, OPERATION, {
        cause,
      }),
    );
  }
  if (fetched.elfBytes.length > MAX_ELF_BYTES)
    return err(
      new AnalysisResourceConstraintError(
        OPERATION,
        "memory",
        `Fetched program ${programId} is ${String(fetched.elfBytes.length)} bytes, above the ${String(MAX_ELF_BYTES)}-byte intake allowance.`,
        { maximum_bytes: MAX_ELF_BYTES },
      ),
    );
  const path = join(outDir, `${programId}.so`);
  try {
    await mkdir(outDir, { recursive: true });
    await writeFile(path, fetched.elfBytes, { signal });
  } catch (cause) {
    return err(
      new ProviderAdapterError(SOLANA_PROGRAM_PROVIDER_IDENTITY.id, OPERATION, {
        cause,
      }),
    );
  }
  return ok({
    bytes: fetched.elfBytes,
    path,
    source: "solana-rpc",
    programId,
    programDataAccount: fetched.programDataAccount,
    slot: fetched.slot,
  });
};

/** Extract printable strings from `.rodata`-family sections with file offsets. */
const extractStrings = (
  image: SolanaElfImage,
): SolanaProgramAnalysis["strings"] => {
  let total = 0;
  const relevant: { value: string; file_offset: number }[] = [];
  for (const section of image.sections) {
    if (section.type !== 1 || !section.name.startsWith(".rodata")) continue;
    const bytes = image.bytes;
    let runStart = -1;
    const flush = (end: number): void => {
      if (runStart < 0 || end - runStart < 4) return;
      total += 1;
      if (relevant.length < MAX_RELEVANT_STRINGS) {
        const value = new TextDecoder("utf-8", { fatal: false }).decode(
          bytes.subarray(runStart, end),
        );
        if (RELEVANT_STRING.test(value))
          relevant.push({ value, file_offset: runStart });
      }
    };
    const limit = Math.min(section.offset + section.size, bytes.length);
    for (let index = section.offset; index < limit; index += 1) {
      const byte = bytes[index] ?? 0;
      if (byte >= 0x20 && byte < 0x7f) {
        if (runStart < 0) runStart = index;
      } else {
        flush(index);
        runStart = -1;
      }
    }
    flush(limit);
  }
  return { total, relevant };
};

const analyzeAcquired = (
  acquired: AcquiredProgram,
): Result<SolanaProgramAnalysis, AnalysisError> => {
  let image: SolanaElfImage;
  try {
    image = parseSolanaElf(acquired.bytes);
  } catch (cause) {
    if (cause instanceof SolanaElfFailure)
      return err(
        new AnalysisUnsupportedTargetError(
          OPERATION,
          acquired.path,
          cause.message,
          {
            cause,
          },
        ),
      );
    return err(
      new ProviderAdapterError(SOLANA_PROGRAM_PROVIDER_IDENTITY.id, OPERATION, {
        cause,
      }),
    );
  }
  if (image.machine !== ELF_MACHINE_BPF)
    return err(
      new AnalysisUnsupportedTargetError(
        OPERATION,
        acquired.path,
        `ELF machine ${String(image.machine)} is not sBPF (EM_BPF 263); this analyzer covers Solana programs only.`,
      ),
    );

  const textSection = solanaTextSection(image);
  const instructions =
    textSection === undefined
      ? []
      : disassembleSbpf(
          acquired.bytes.subarray(
            textSection.offset,
            textSection.offset + textSection.size,
          ),
          textSection.address,
          textSection.offset,
        );
  const handlers = scanSolanaDispatch(instructions);
  const tagDispatch = scanSolanaTagDispatch(instructions);
  const limitations = [...BASE_LIMITATIONS];
  if (textSection === undefined)
    limitations.push(
      "The ELF carries no .text section; no disassembly or dispatch scan was possible.",
    );
  if (image.trailingBytes > 0)
    limitations.push(
      `The artifact carries ${String(image.trailingBytes)} trailing bytes beyond its ELF-declared extents (typical of account-capacity dumps); identity covers the whole file.`,
    );
  if (acquired.source === "solana-rpc")
    limitations.push(
      "Fetched at finalized commitment from the selected RPC endpoint; the deployed program may differ from any earlier capture if it was upgraded.",
    );

  const definedSymbols = image.dynamicSymbols.filter(
    (symbol) => symbol.sectionIndex !== 0,
  ).length;
  const undefinedSymbols = image.dynamicSymbols.filter(
    (symbol) => symbol.sectionIndex === 0 && symbol.name.length > 0,
  );

  const report: SolanaProgramAnalysis = {
    artifact: {
      path: acquired.path,
      sha256: createHash("sha256").update(acquired.bytes).digest("hex"),
      bytes: acquired.bytes.length,
      source: acquired.source,
      program_id: acquired.programId,
      program_data_account: acquired.programDataAccount,
      slot: acquired.slot,
    },
    elf: {
      bits: 64,
      byte_order: image.byteOrder,
      elf_type: image.elfType,
      machine: image.machine,
      machine_name: solanaElfMachineName(image.machine),
      entrypoint: image.entrypoint,
      program_header_count: image.programHeaders.length,
      section_header_count: image.sections.length,
      trailing_bytes: image.trailingBytes,
      sections: image.sections.map((section) => ({
        name: section.name,
        type: section.type,
        address: section.address,
        offset: section.offset,
        size: section.size,
      })),
    },
    disassembly: {
      engine: "rea-sbpf-decoder",
      text_section: textSection?.name ?? null,
      instruction_count: instructions.length,
      unknown_opcodes: instructions.filter(isUnknownSbpfInstruction).length,
      call_sites: instructions.filter(
        (instruction) => instruction.mnemonic === "call",
      ).length,
      exit_sites: instructions.filter(
        (instruction) => instruction.mnemonic === "exit",
      ).length,
      lddw_constants: instructions.filter(
        (instruction) => instruction.mnemonic === "lddw",
      ).length,
      coverage: textSection === undefined ? "no-text-section" : "complete",
    },
    handlers: handlers.map((handler) => ({
      discriminator: handler.discriminator,
      constant_address: handler.constantAddress,
      constant_file_offset: handler.constantFileOffset,
      comparison_address: handler.comparisonAddress,
      branch: handler.branch,
      branch_target: handler.branchTarget,
      value_register: handler.valueRegister,
      constant_register: handler.constantRegister,
    })),
    tag_dispatch: tagDispatch.map((tree) => ({
      root: tree.root,
      load_address: tree.loadAddress,
      tag_register: tree.tagRegister,
      load_base_register: tree.loadBaseRegister,
      load_offset: tree.loadOffset,
      compare_count: tree.compareCount,
      handlers: tree.handlers.map((h) => ({ tag: h.tag, target: h.target })),
      default_targets: [...tree.defaultTargets],
    })),
    syscalls: {
      dynamic_symbols: undefinedSymbols.map((symbol) => symbol.name).sort(),
      defined_symbols: definedSymbols,
      undefined_symbols: undefinedSymbols.length,
    },
    strings: extractStrings(image),
    limitations,
  };
  return ok(report);
};

/** Write the human-facing artifacts next to the machine Evidence when out_dir was selected. */
const writeArtifacts = async (
  input: AnalyzeSolanaProgramInput,
  acquired: AcquiredProgram,
  report: SolanaProgramAnalysis,
): Promise<AnalysisError | undefined> => {
  if (input.out_dir === undefined) return undefined;
  try {
    await mkdir(input.out_dir, { recursive: true });
    await writeFile(
      join(input.out_dir, "solana-analysis.json"),
      `${JSON.stringify(report, null, 2)}\n`,
    );
    if (report.disassembly.coverage === "complete") {
      const image = parseSolanaElf(acquired.bytes);
      const textSection = solanaTextSection(image);
      if (textSection !== undefined) {
        const lines = disassembleSbpf(
          acquired.bytes.subarray(
            textSection.offset,
            textSection.offset + textSection.size,
          ),
          textSection.address,
          textSection.offset,
        ).map(
          (instruction) =>
            `${instruction.address.toString(16).padStart(8, "0")}  ${instruction.text}`,
        );
        await writeFile(
          join(input.out_dir, "disassembly.txt"),
          `${lines.join("\n")}\n`,
        );
      }
    }
    return undefined;
  } catch (cause) {
    return new ProviderAdapterError(
      SOLANA_PROGRAM_PROVIDER_IDENTITY.id,
      OPERATION,
      { cause },
    );
  }
};

/** In-process Solana program analyzer: ELF intake, sBPF disassembly, Anchor dispatch scan. */
export class SolanaProgramProvider implements SolanaProgramPort {
  readonly identity = SOLANA_PROGRAM_PROVIDER_IDENTITY;

  constructor(
    private readonly defaults: {
      readonly rpcUrl?: string;
    } = {},
  ) {}

  async analyze(
    input: AnalyzeSolanaProgramInput,
    options?: ExecutionOptions,
  ): Promise<Result<SolanaProgramAnalysis, AnalysisError>> {
    const signal = options?.signal;
    const acquired =
      input.path !== undefined
        ? await readLocalElf(input.path, signal)
        : await fetchProgramElf(
            input,
            input.rpc_url ?? this.defaults.rpcUrl ?? DEFAULT_SOLANA_RPC_URL,
            signal,
          );
    if (!acquired.ok) return acquired;
    const report = analyzeAcquired(acquired.value);
    if (!report.ok) return report;
    const writeFailure = await writeArtifacts(
      input,
      acquired.value,
      report.value,
    );
    if (writeFailure !== undefined) return err(writeFailure);
    return report;
  }
}
