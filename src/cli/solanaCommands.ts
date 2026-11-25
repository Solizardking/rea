import type { Logger } from "pino";

import {
  createSolanaFormalVerificationService,
  createSolanaProgramBatchService,
  createSolanaProgramService,
  createSolanaReceiptsService,
} from "../composition/solana.js";
import { SOLANA_TOOL_CONTRACTS } from "../contracts/solana/solanaToolContracts.js";
import { SOLANA_PROGRAM_PROVIDER_IDENTITY } from "../solana/SolanaProviderIdentity.js";
import { contractNamed } from "./contractCliDescription.js";
import {
  registerContractCommand,
  type ContractCommandContext,
} from "./contractCommand.js";
import {
  analyzeWithService,
  inspectWithService,
} from "./contractCommandRunners.js";
import type { CliInstance } from "./types.js";

const PROVIDER_ID = SOLANA_PROGRAM_PROVIDER_IDENTITY.id;
/** The caller path recorded as the formal-verification command's subject, in preference order. */
const FORMAL_PRIMARY_PATHS = [
  "analysis_path",
  "certora_verdicts_path",
  "aristotle_properties_path",
  "out_path",
] as const;

/**
 * Record the caller's own spelling of whichever path selected the program:
 * the ELF path, else the out_dir that receives an RPC-fetched ELF. With
 * neither, the shared workflow reports the missing selection itself.
 */
const inspectSelectedProgram =
  (environment: Readonly<NodeJS.ProcessEnv>) =>
  (input: unknown, context: ContractCommandContext) => {
    const service = () => createSolanaProgramService(environment);
    if (context.callerInputs["path"] !== undefined)
      return inspectWithService(service, PROVIDER_ID, "path")(input, context);
    if (context.callerInputs["out_dir"] !== undefined)
      return inspectWithService(
        service,
        PROVIDER_ID,
        "out_dir",
      )(input, context);
    return analyzeWithService(service, PROVIDER_ID)(input, context);
  };

/** Resolve operator paths and run the Solana workflows shared with MCP. */
export const registerSolanaCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv>,
): void => {
  registerContractCommand(
    cli,
    logger,
    contractNamed(SOLANA_TOOL_CONTRACTS, "analyze_solana_program"),
    {
      description:
        "Analyze a Solana sBPF program from a local ELF or by program id via read-only RPC",
      callerPaths: ["path", "out_dir"],
      fields: {
        path: { description: "Local sBPF ELF to analyze" },
        program_id: {
          description: "Program id (base58) to fetch through Solana JSON-RPC",
        },
        rpc_url: {
          description:
            "Solana JSON-RPC URL; defaults to REA_SOLANA_RPC_URL or public mainnet",
        },
        out_dir: {
          description:
            "Absent or empty output directory for the fetched ELF and analysis artifacts; required with program_id",
        },
        handoff: {
          description:
            "Write the deep-decompiler handoff artifact under <out_dir>/handoff",
        },
        instruction_names: {
          description:
            "Anchor instruction names (e.g. from an IDL) to confirm against handler discriminators",
        },
      },
    },
    inspectSelectedProgram(environment),
  );

  registerContractCommand(
    cli,
    logger,
    contractNamed(SOLANA_TOOL_CONTRACTS, "analyze_solana_programs"),
    {
      description:
        "Analyze a batch of Solana sBPF programs (local ELFs, program ids, or a directory of .so captures) with per-item outputs and an index",
      callerPaths: ["out_dir", "dir"],
      jsonText: ["items"],
      fields: {
        items: {
          description:
            'JSON array of items: [{"path":"/abs/a.so"},{"program_id":"..."}]',
        },
        dir: { description: "Directory whose .so files join the batch" },
        out_dir: {
          description:
            "Absent or empty directory receiving one subdirectory per item plus index.json",
        },
        concurrency: {
          description: "Maximum items analyzed at once (default 4, cap 8)",
        },
        handoff: {
          description:
            "Write the deep-decompiler handoff artifact into every item directory",
        },
        instruction_names: {
          description:
            "Anchor instruction names to confirm against handler discriminators for every item",
        },
      },
    },
    inspectWithService(
      () => {
        const batch = createSolanaProgramBatchService(environment);
        return {
          inspect: (input: unknown, options?: { signal?: AbortSignal }) =>
            batch.inspectBatch(input, options),
          close: () => batch.close(),
        };
      },
      PROVIDER_ID,
      "out_dir",
    ),
  );

  registerContractCommand(
    cli,
    logger,
    contractNamed(SOLANA_TOOL_CONTRACTS, "solana_receipts"),
    {
      description:
        "Build differential-verification receipts for Solana program analyses from a caller-supplied evidence JSON",
      callerPaths: ["analysis_path", "out_dir", "evidence_path"],
      fields: {
        analysis_path: {
          description: "Path to one solana-analysis.json to receipt",
        },
        out_dir: {
          description:
            "Output directory of a single or batch analysis run; receipts are written into it",
        },
        evidence_path: {
          description:
            "Differential evidence JSON: one program document, or an array of documents for a batch",
        },
      },
    },
    inspectWithService(
      () => {
        const receipts = createSolanaReceiptsService();
        return {
          inspect: (input: unknown, options?: { signal?: AbortSignal }) =>
            receipts.buildReceipts(input, options),
          close: () => receipts.close(),
        };
      },
      PROVIDER_ID,
      "evidence_path",
    ),
  );

  registerContractCommand(
    cli,
    logger,
    contractNamed(SOLANA_TOOL_CONTRACTS, "solana_formal_verification"),
    {
      description:
        "Normalize Certora Prover and Harmonic Aristotle verdict reports for a Solana program, bound to its analyzed artifact",
      callerPaths: [
        "analysis_path",
        "certora_verdicts_path",
        "aristotle_properties_path",
        "out_path",
      ],
      fields: {
        analysis_path: {
          description: "solana-analysis.json of the program the reports verify",
        },
        verified_artifact_sha256: {
          description:
            "SHA-256 of the artifact the prover runs used; must match the analysis",
        },
        certora_verdicts_path: {
          description:
            "prover-cli --job-id <id> --verdicts --format json output",
        },
        aristotle_properties_path: {
          description: "aristotle properties <project-id> --json output",
        },
        out_path: {
          description:
            "New report path; defaults to formal-verification.json beside the analysis",
        },
      },
    },
    (input: unknown, context: ContractCommandContext) => {
      const service = () => {
        const formal = createSolanaFormalVerificationService(environment);
        return {
          inspect: (value: unknown, options?: { signal?: AbortSignal }) =>
            formal.normalize(value, options),
          close: () => formal.close(),
        };
      };
      const primary = FORMAL_PRIMARY_PATHS.find(
        (field) => context.callerInputs[field] !== undefined,
      );
      return primary === undefined
        ? analyzeWithService(service, PROVIDER_ID)(input, context)
        : inspectWithService(service, PROVIDER_ID, primary)(input, context);
    },
  );
};
