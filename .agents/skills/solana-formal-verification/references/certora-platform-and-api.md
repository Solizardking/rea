# Certora hosted platform and REST API

Detail behind the platform sections of the skill, assembled from the AutoProver user manual the dev supplied on 2026-11-24. The classic certoraRun route in the skill stays the verified Solana path. Everything here is documented behavior of the hosted platform, and the parts that would touch Solana files directly are flagged as untested where the manual leaves them open.

## Hosted engines and language support

- AutoProver extracts intent from source code, comments, and design documents, formalizes the intent into implementation independent properties, and compiles the properties into CVL rules verified by the Certora Prover. A plain language design document improves inference quality and is not required.

- AutoFuzzer compiles the same generated properties into concrete scenario and Foundry fuzz tests.

- AI Auditor is language agnostic and finds issues in code and design documents in any language. It is the only hosted engine that reads Rust today.

- AutoProver and AutoFuzzer support Solidity only, and AutoProver is in beta. Rust support for both engines is planned for a future release.

- All in one runs AI Auditor, AutoProver, and AutoFuzzer together over up to three Solidity contracts. Its AI Auditor portion can also inspect other languages.

- AutoProver run modes are Prioritized, Comprehensive, Evaluate, and Property generation. Prioritized selects the top ranked property and its supporting cluster, Comprehensive formalizes all candidate properties, Property generation stops after inferring properties, and Evaluate writes no specs of its own.

- Reports can be shared outside the organization through a password protected read only link in the report header. Shared copies leave out billing, instructions, context files, and triage verdicts, and All in one reports cannot be shared yet.

## Evaluate mode in detail

- Evaluate judges specs and confs already in the repository. The run form selects it automatically when it finds spec and conf files in a certora folder or beside a spec, and it warns when a repository has nothing to evaluate.

- The report opens with property coverage, meaning how many inferred properties the rules attempt, CVL faithfulness, meaning how faithfully the rules encode the attempted properties as exact, partial, or wrong, and rule execution, meaning how many confs ran and what their rules returned.

- Spec coverage lists each spec with the confs it ran under and links to each conf prover run. Mutation testing lists the bugs the evaluation injected, whether a rule caught each one, and links to the prover jobs that checked it.

- An Evaluate run carries a fixed estimate of 150 USD before any plan discount. Design and threat model documents in Evaluate mode only shape the inferred properties.

- Treat Solana support as an open question. The manual documents Evaluate inside the Solidity pipeline and never mentions CVLR or Solana files, and nobody on this team has run it against a Solana suite.

## REST API connection

- Create scoped organization API keys under API in the organization sidebar, where the live OpenAPI 3.1 reference also lives. Authenticate requests with an Authorization Bearer header.

- Launch endpoints are version 2 and strict per workflow. The paths are POST /v2/ai-auditor-full-runs, POST /v2/ai-auditor-diff-runs, POST /v2/ai-auditor-finding-validations-runs, POST /v2/auto-prover-runs, and POST /v2/auto-fuzzer-runs.

- Append /estimate to any launch endpoint to quote the same request without reserving balance. AutoProver and AutoFuzzer estimates return a short lived estimate quote ID.

- Pin a reviewed estimate by sending its quote ID in the Estimate-Quote-Id header at launch. The quote expires after 15 minutes and binds to the organization key, the engine, the repository, the commit, and the contract, and a mismatch or an expiry means estimating again.

- Send an Idempotency-Key header with a stable non empty value of at most 200 characters on launches. A retry with the same key, the same idempotency value, and an identical body recovers the accepted run without a fresh estimate or a second reservation, even after 24 hours, and reusing the key with a different body returns a conflict.

- Read key scopes and enabled workflows from GET /v2/access before assuming a key can launch a given engine.

- List and recover runs through GET /v2/runs with cursor pagination, and read one run through GET /v2/runs/{run_id}, which returns status, embedded progress, billing, result availability, and delivery state in one resource.

- Fetch outcomes from GET /v2/runs/{run_id}/result once a run succeeds, and list downloadable outputs through GET /v2/runs/{run_id}/artifacts, following the cursor until it returns null. Request cancellation through POST /v2/runs/{run_id}/cancel, which is safe to repeat.

- Poll the run resource no faster than every 15 seconds and back off after transient failures while honoring Retry-After. A run reports finalizing while provider completion, billing settlement, and result publication converge, and only then turns succeeded.

- Expect errors as application/problem+json with the real HTTP status, a stable code, a request ID, and a retryable flag. Branch on the code and the retryable flag, never on the human readable detail text, and treat unknown versioned endpoints as JSON 404 responses with code endpoint_not_found.

- Respect the public automation buckets per organization. The limits are 50 launches per rolling hour, 120 estimates per rolling hour, 1000 general reads per rolling hour, 120 generated file delivery requests per rolling hour, and 30 artifact list requests per rolling minute, and downloading a signed artifact URL consumes no bucket.

- Keep request bodies small and exact. Bodies are strict, capped at 256 KiB, and reject unknown properties, and every source resolves to an immutable 40 character commit SHA before any quote or reservation.

- Deliver generated files back to a repository by binding a launch to an open same repository pull request in its delivery field, then calling POST /v2/runs/{run_id}/generated-files/commit after the run succeeds. The organization GitHub App performs the write and the call is idempotent.

## Keys, billing, and CI

- Treat an API key as borrowed identity. It is scoped to one organization, tied to its creator, and dies when the creator leaves or is banned or when the key expires or is revoked, so offboarding means creating a replacement under a remaining member and revoking the old key.

- Enable Use Certora Prover when creating a key meant for classic verification. The Certora Prover access and billing guide covers the Free plan keys, the monthly verification minutes, and replacing a key that lacks the permission.

- Fund hosted engine work from the prepaid USD organization balance, which an owner tops up through Stripe checkout and which never expires. A reservation holds during the run, the final charge takes the actual billable amount, and plan discounts apply automatically.

- Expect classic prover verification to bill separately. Its monthly free minutes and metered billing never cover hosted engine runs, and engine balances never cover prover minutes.

- Install the GitHub Action integration from the sidebar on an eligible plan when a connected repository wants hosted engine checks in CI. The installer opens a pull request with a workflow for AI Auditor, AutoProver, or AutoFuzzer, and the engines fail the check only when the normalized outcome is issues_found, with coverage gaps reported as warnings.
