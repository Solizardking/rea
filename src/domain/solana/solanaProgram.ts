import { z } from "zod";

import { digestSchema } from "../digests.js";
import {
  absoluteLocalPathStringSchema,
  localPathStringSchema,
} from "../localPath.js";

const byteOffset = z.int().nonnegative();
const discriminatorSchema = z.string().regex(/^[a-f0-9]{16}$/);
/** Solana public keys are base58 encodings of 32 bytes (32–44 characters). */
export const solanaPublicKeySchema = z
  .string()
  .regex(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/);

/**
 * Select exactly one program source: an explicit local sBPF ELF, or a program
 * id whose executable is fetched read-only through Solana JSON-RPC. RPC intake
 * materializes the fetched ELF under `out_dir`, so the analyzed artifact is a
 * caller-selected local file with the same identity semantics as `--elf`.
 */
export const analyzeSolanaProgramInputSchema = z
  .strictObject({
    path: absoluteLocalPathStringSchema
      .optional()
      .describe("Absolute path to a caller-selected local sBPF ELF"),
    program_id: solanaPublicKeySchema
      .optional()
      .describe("Base58 program id to fetch through Solana JSON-RPC"),
    rpc_url: z
      .url()
      .optional()
      .describe(
        "Solana JSON-RPC endpoint for program_id intake; defaults to REA_SOLANA_RPC_URL or the public mainnet endpoint",
      ),
    out_dir: absoluteLocalPathStringSchema
      .optional()
      .describe(
        "Directory receiving the fetched ELF (required with program_id) and, when selected, the analysis artifacts",
      ),
  })
  .superRefine((value, context) => {
    const hasPath = value.path !== undefined;
    const hasProgram = value.program_id !== undefined;
    if (hasPath === hasProgram)
      context.addIssue({
        code: "custom",
        path: ["path"],
        message:
          "Select exactly one program source: a local ELF path or a program id.",
      });
    if (hasProgram && value.out_dir === undefined)
      context.addIssue({
        code: "custom",
        path: ["out_dir"],
        message:
          "Program-id intake materializes the fetched ELF under out_dir; select it explicitly.",
      });
    if (hasPath && value.rpc_url !== undefined)
      context.addIssue({
        code: "custom",
        path: ["rpc_url"],
        message: "rpc_url applies only to program-id intake.",
      });
  });

const sectionSchema = z.strictObject({
  name: z.string(),
  type: z.int().nonnegative(),
  address: byteOffset,
  offset: byteOffset,
  size: byteOffset,
});

/**
 * Observed ELF/RPC facts plus inferred Anchor dispatch candidates. Handler
 * rows are reconstruction leads recovered from the lddw-constant dispatch
 * idiom; they are not a verified instruction inventory.
 */
export const solanaProgramAnalysisSchema = z
  .strictObject({
    artifact: z.strictObject({
      path: localPathStringSchema,
      sha256: digestSchema,
      bytes: byteOffset,
      source: z.enum(["local-file", "solana-rpc"]),
      program_id: z.string().nullable(),
      program_data_account: z.string().nullable(),
      slot: byteOffset.nullable(),
    }),
    elf: z.strictObject({
      bits: z.literal(64),
      byte_order: z.enum(["little", "big"]),
      elf_type: z.int().nonnegative(),
      machine: z.int().nonnegative(),
      machine_name: z.string(),
      entrypoint: byteOffset,
      program_header_count: z.int().nonnegative(),
      section_header_count: z.int().nonnegative(),
      /** File bytes beyond the extents declared by the ELF headers. */
      trailing_bytes: byteOffset,
      sections: z.array(sectionSchema),
    }),
    disassembly: z.strictObject({
      engine: z.literal("rea-sbpf-decoder"),
      text_section: z.string().nullable(),
      instruction_count: z.int().nonnegative(),
      unknown_opcodes: z.int().nonnegative(),
      call_sites: z.int().nonnegative(),
      exit_sites: z.int().nonnegative(),
      lddw_constants: z.int().nonnegative(),
      coverage: z.enum(["complete", "no-text-section"]),
    }),
    handlers: z.array(
      z.strictObject({
        discriminator: discriminatorSchema,
        constant_address: byteOffset,
        constant_file_offset: byteOffset,
        comparison_address: byteOffset,
        branch: z.enum(["jeq", "jne"]),
        branch_target: byteOffset,
        value_register: z.int().min(0).max(15),
        constant_register: z.int().min(0).max(15),
      }),
    ),
    /** 1-byte instruction-tag dispatch trees (Shank/Borsh native programs). */
    tag_dispatch: z.array(
      z.strictObject({
        load_address: byteOffset,
        tag_register: z.int().min(0).max(15),
        load_base_register: z.int().min(0).max(15),
        load_offset: z.int(),
        compare_count: z.int().nonnegative(),
        handlers: z.array(
          z.strictObject({ tag: z.int().min(0).max(255), target: byteOffset }),
        ),
        default_targets: z.array(byteOffset),
      }),
    ),
    syscalls: z.strictObject({
      dynamic_symbols: z.array(z.string()),
      defined_symbols: z.int().nonnegative(),
      undefined_symbols: z.int().nonnegative(),
    }),
    strings: z.strictObject({
      total: z.int().nonnegative(),
      relevant: z.array(
        z.strictObject({ value: z.string(), file_offset: byteOffset }),
      ),
    }),
    limitations: z.array(z.string()),
  })
  .superRefine((value, context) => {
    for (const [index, handler] of value.handlers.entries())
      if (handler.constant_file_offset >= value.artifact.bytes)
        context.addIssue({
          code: "custom",
          path: ["handlers", index, "constant_file_offset"],
          message: "Handler constant lies outside the analyzed artifact.",
        });
    const seen = new Set<string>();
    for (const handler of value.handlers)
      if (seen.has(handler.discriminator))
        context.addIssue({
          code: "custom",
          path: ["handlers"],
          message: "Handler candidates must not repeat a discriminator.",
        });
      else seen.add(handler.discriminator);
  });

export type AnalyzeSolanaProgramInput = z.infer<
  typeof analyzeSolanaProgramInputSchema
>;
export type SolanaProgramAnalysis = z.infer<typeof solanaProgramAnalysisSchema>;
