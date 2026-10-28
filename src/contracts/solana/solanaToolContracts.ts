import {
  analyzeSolanaProgramInputSchema,
  solanaProgramAnalysisSchema,
} from "../../domain/solana/solanaProgram.js";
import {
  solanaReceiptsInputSchema,
  solanaReceiptsResultSchema,
} from "../../domain/solana/solanaReceipts.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Solana program analysis is independent of active native-analysis providers and host toolchains. */
export const ANALYZE_SOLANA_PROGRAM_CONTRACT = {
  name: "analyze_solana_program",
  ...toolContractMetadata("analyze_solana_program"),
  kind: "artifact-provider",
  requiresActiveTarget: true,
  description:
    "Analyze one Solana sBPF program from an explicit local ELF path, or fetch its executable read-only by program id through Solana JSON-RPC (BPF Loader Upgradeable ProgramData layout; rpc_url or REA_SOLANA_RPC_URL selects the endpoint, default public mainnet). Program-id intake materializes the fetched ELF as <out_dir>/<program_id>.so and requires out_dir; when out_dir is selected, solana-analysis.json and disassembly.txt are also written there. Returns artifact identity (SHA-256 over the whole file, including any trailing account-capacity padding), ELF64 sections and entrypoint, a linear-sweep sBPF disassembly summary from the bundled decoder (instruction/call/exit counts), dynamic syscall symbols, bounded .rodata strings, and Anchor handler candidates recovered from the lddw-constant dispatch-comparison idiom (discriminator, constant/comparison addresses, branch target). Handler candidates are reconstruction leads, not a verified instruction inventory: table dispatch and split compares are not recovered, no Rust source/types/control flow is lifted, the target is never executed, and no transaction is built or broadcast. Parity with a deployed program is established only by differential tests against the captured original.",
  inputSchema: analyzeSolanaProgramInputSchema,
  outputSchema: evidenceResultOf(solanaProgramAnalysisSchema),
  examples: [
    {
      title: "Analyze a captured program ELF",
      input: { path: "/artifacts/pump_amm.so" },
    },
    {
      title: "Fetch and analyze a deployed program by id",
      input: {
        program_id: "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA",
        out_dir: "/artifacts/pump_amm",
      },
    },
  ],
} as const satisfies ToolContract;

/** Receipt binding: promotes instruction claims only when local-runner receipts match the artifact SHA-256. */
export const SOLANA_RECEIPTS_CONTRACT = {
  name: "solana_receipts",
  ...toolContractMetadata("solana_receipts"),
  kind: "artifact-provider",
  requiresActiveTarget: true,
  description:
    'Bind differential receipts (rea.solana-receipts/v1, recorded by a local LiteSVM-style harness) to one Solana sBPF ELF. Hashes the selected ELF and checks it equals the receipts\' artifact_sha256, that the engine is a supported local runtime (litesvm, solana-test-validator, surfpool, mollusk) and that its network is "none". Per instruction tag, a claim becomes receipt-verified only when the binding holds, at least one positive receipt passed and no receipt failed; every other claim is downgraded to lead with the reason. REA never loads the program or replays transactions; it audits recorded receipts.',
  inputSchema: solanaReceiptsInputSchema,
  outputSchema: evidenceResultOf(solanaReceiptsResultSchema),
  examples: [
    {
      title: "Bind LiteSVM receipts to a captured ELF",
      input: {
        path: "/artifacts/core.so",
        receipts_path: "/artifacts/receipts.json",
      },
    },
  ],
} as const satisfies ToolContract;

/** Preserve the default catalog's exact operation and ordering. */
export const SOLANA_TOOL_CONTRACTS = [
  ANALYZE_SOLANA_PROGRAM_CONTRACT,
  SOLANA_RECEIPTS_CONTRACT,
] as const satisfies readonly ToolContract[];
