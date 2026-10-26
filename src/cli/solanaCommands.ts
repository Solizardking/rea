import { z } from "incur";
import { solanaProgramModule } from "../composition/solana.js";
import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import {
  analysisEvidenceDeliveryOptions,
  deliverCliAnalysisEvidence,
} from "./analysisEvidenceDelivery.js";
import { localPathStringSchema } from "../domain/localPath.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";

/** Resolve caller paths and analyze one Solana program through the shared workflow. */
export const registerSolanaCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv>,
): void => {
  const service = solanaProgramModule.create(environment);
  cli.command(solanaProgramModule.cliCommand, {
    description:
      "Analyze a Solana sBPF program from a local ELF or by program id via read-only RPC",
    args: z.object({}),
    options: z.object({
      elf: localPathStringSchema
        .optional()
        .describe("Local sBPF ELF to analyze"),
      program: z
        .string()
        .optional()
        .describe("Program id (base58) to fetch through Solana JSON-RPC"),
      rpcUrl: z
        .string()
        .optional()
        .describe(
          "Solana JSON-RPC URL; defaults to REA_SOLANA_RPC_URL or public mainnet",
        ),
      out: localPathStringSchema
        .optional()
        .describe(
          "Output directory for fetched ELF and analysis artifacts; required with --program",
        ),
      evidence_output: analysisEvidenceDeliveryOptions.evidence_output,
    }),
    run: ({ options }) =>
      withCommandCancellation(async (signal) =>
        logCliCommand(logger, solanaProgramModule.cliCommand, async () =>
          deliverCliAnalysisEvidence({
            run: () =>
              service.inspect(
                {
                  ...(options.elf === undefined
                    ? {}
                    : { path: absoluteCallerPath(options.elf) }),
                  ...(options.program === undefined
                    ? {}
                    : { program_id: options.program }),
                  ...(options.rpcUrl === undefined
                    ? {}
                    : { rpc_url: options.rpcUrl }),
                  ...(options.out === undefined
                    ? {}
                    : { out_dir: absoluteCallerPath(options.out) }),
                },
                { signal },
              ),
            service,
            providerId: "solana-sbpf",
            operation: "analyze_solana_program",
            signal,
            detail: "complete",
            evidenceOutput: options.evidence_output,
          }),
        ),
      ),
  });
};
