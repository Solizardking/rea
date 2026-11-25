import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  SolanaFormalVerificationInput,
  SolanaFormalVerificationResult,
} from "../../domain/solana/solanaFormalVerification.js";
import type { Result } from "../../domain/result.js";

/** Replaceable formal-verification report normalizer: Certora and Aristotle reports bound to a Solana artifact. */
export interface SolanaFormalVerificationPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  normalize(
    input: SolanaFormalVerificationInput,
    options?: ExecutionOptions,
  ): Promise<Result<SolanaFormalVerificationResult, AnalysisError>>;
}
