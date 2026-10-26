import { SolanaProgramService } from "../application/solana/SolanaProgramService.js";
import { SolanaProgramProvider } from "../solana/SolanaProgramProvider.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { ANALYZE_SOLANA_PROGRAM_CONTRACT } from "../contracts/solana/solanaToolContracts.js";

/**
 * Compose the in-process Solana analyzer without import-time I/O. The
 * optional REA_SOLANA_RPC_URL environment value only defaults the endpoint
 * for program-id intake; each call may override it with rpc_url.
 */
export const createSolanaProgramService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): SolanaProgramService =>
  new SolanaProgramService(
    new SolanaProgramProvider(
      environment.REA_SOLANA_RPC_URL === undefined
        ? {}
        : { rpcUrl: environment.REA_SOLANA_RPC_URL },
    ),
  );

/**
 * Static binding of the operation, command and fresh service factory.
 * Construction performs no acquisition, target I/O or import-time execution.
 */
export const solanaProgramModule = {
  contract: ANALYZE_SOLANA_PROGRAM_CONTRACT,
  cliCommand: CLI_COMMANDS.analyzeSolanaProgram,
  create: createSolanaProgramService,
} as const;
