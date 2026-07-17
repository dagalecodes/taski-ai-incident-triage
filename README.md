# Taski AI Incident Triage

Taski AI Incident Triage is a contract-first Azure Monitor incident intake service for Taski. This repository owns alert validation, normalization, queued delivery, and authenticated forwarding; it does not contain or replace the Taski application.

## Batch 5C Phase 1 controlled integration harness

The Batch 5C CLI reuses the production alert schema, normalization, queue processor, Taski client, exact-byte signing, response schemas, triage schema, and final output guardrail. It is a pre-deployment validation harness, not a second pipeline.

The default is a deterministic dry run with simulated strict Taski responses and zero network calls:

```powershell
npm.cmd run --silent demo:triage
npm.cmd run --silent demo:triage -- --scenario duplicate-terminal
npm.cmd run --silent demo:triage -- --scenario resolved
```

Other network-free scenarios are `stale`, `model-failure`, and `result-delivery-failure`. Output is one safe JSON summary containing only mode, scenario, incident correlation/status, whether triage ran, safe delivery status, and safe analysis identity. It never prints diagnosis prose, request bodies, headers, signatures, raw responses, diagnostic context, keys, or secrets.

For an explicitly requested safe failure category, add `--diagnose-safe-stage`. The flag does not enable delivery and does not replace either staging confirmation:

```powershell
npm.cmd run --silent demo:triage -- --diagnose-safe-stage
npm.cmd run --silent demo:triage -- --diagnose-safe-stage --scenario result-delivery-failure
```

Diagnostic mode emits only a fixed stage identifier plus the last numeric Taski HTTP status and existing safe pipeline category when available. It never emits URLs, bodies, headers, credentials, signatures, diagnosis content, raw exceptions, or stacks. Without delivery flags it remains a network-free dry run; confirmed staging diagnostics still require both `--deliver-staging` and `--confirm-staging-delivery`.

The following deterministic staging command is documented for later operator use only. **Do not run until manually authorized.** Both delivery flags are mandatory, OpenAI is not called, and the destination must be exactly `https://taski-staging.azurewebsites.net` or `http://localhost:3000`:

```powershell
npm.cmd run --silent demo:triage -- --deliver-staging --confirm-staging-delivery
```

Required environment variable names are `TASKI_INTERNAL_BASE_URL`, `TASKI_INCIDENT_KEY_ID`, `TASKI_INCIDENT_SECRET`, and `TRIAGE_POLICY_VERSION`; `TASKI_REQUEST_TIMEOUT_MS` is optional. Secrets are never accepted as CLI arguments.

Live OpenAI staging mode is optional, billable, and separately gated. **Do not run without explicit authorization for both staging delivery and the OpenAI charge:**

```powershell
npm.cmd run --silent demo:triage -- --deliver-staging --confirm-staging-delivery --use-openai --confirm-openai-charge
```

It additionally requires `OPENAI_API_KEY` and `OPENAI_MODEL`; `OPENAI_REQUEST_TIMEOUT_MS`, `OPENAI_MAX_TURNS`, and `OPENAI_TRACING_ENABLED` are optional bounded settings. Tracing remains disabled unless explicitly enabled.

The deterministic fallback is low-confidence, contains no evidence, requires human approval for every recommendation, and states that neither live telemetry nor OpenAI was used. Dry runs create no state and need no cleanup. An authorized staging delivery intentionally persists synthetic incident data in Taski; no automatic rollback or deletion is attempted, so any cleanup must be separately authorized and performed through Taski's normal controls. The harness creates no Azure resources and performs no remediation.

## Batch 5B local AI worker

Batch 5B adds an undeployed, guarded incident-triage worker after Taski incident persistence. It uses one Agent from the official `@openai/agents` SDK and imports `src/contracts/triageResult.ts` directly as its structured `outputType`. It does not use handoffs, MCP, hosted shell, computer use, code interpreter, arbitrary network tools, or remediation.

```text
normalized queue incident
  -> validate again
  -> exact-byte HMAC Taski incident ingestion
  -> resolved or stale: complete without OpenAI
  -> matching accepted terminal analysisId: complete without OpenAI
  -> other fired created, updated, or duplicate: guarded triage
  -> exact-byte HMAC Taski triage-result delivery
```

Taski returns the current safe `analysisId` and `analysisStatus` with incident ingestion. An exact policy-bound ID match in `ready`, `failed`, or `not_required` suppresses a paid rerun after Taski accepted a prior result but its HTTP response was lost. Null, different-policy, and nonterminal identities remain eligible. Taski result-delivery failures and real conflicts are thrown for normal Azure Queue retry and poison handling; there is no internal retry loop.

This recovery check is not a distributed claim or lease. Simultaneous duplicate workers can both begin analysis before either result is accepted, so Batch 5B does not claim exactly-once OpenAI execution.

The five tools are `get_service_health`, `get_recent_error_summary`, `get_resource_metrics`, `get_latest_deployment`, and `get_matching_runbook`. They accept strict empty inputs and receive the current bounded incident through injected providers, preventing model-selected resources. Batch 5B's runtime provider returns safe unavailable results; deterministic tests inject sanitized fixtures. Real Azure diagnostic providers are deferred to Batch 6.

Input and tool output are bounded, secret-redacted, and stripped of prompt-injection-like instructions. Final evidence must exactly match the tool evidence ledger. Command/script-like actions, secret-bearing output, fabricated evidence, and unsafe references are rejected. Runbook references are plain evidence only, with no clickable action.

Additional required settings are:

- `OPENAI_API_KEY`
- `OPENAI_MODEL` (explicit; the application does not choose an undocumented default)
- `OPENAI_REQUEST_TIMEOUT_MS` (default 30000; 1000-120000)
- `OPENAI_MAX_TURNS` (default 6; 1-8)
- `OPENAI_TRACING_ENABLED` (default `false`; literal `true` opts in)
- `TRIAGE_POLICY_VERSION` (included in deterministic `analysisId`)

Agents SDK tracing is disabled by default and sensitive trace data capture remains disabled after opt-in. Enabling tracing may still export workflow/tool operational metadata, so it requires a privacy review. Tests never export traces or make live OpenAI, Azure, Taski, or diagnostic-provider calls.

## Batch 4 status

Batch 4 implements a local Azure Functions-compatible queue-first pipeline:

- an Azure Functions Node.js v4 HTTP receiver for Common Alert Schema payloads;
- strict Batch 1 validation and deterministic normalization;
- a Storage Queue output binding containing only the normalized incident;
- a queue-triggered processor that validates the message again;
- exact-byte HMAC-SHA256 signing and bounded Taski HTTP forwarding;
- deterministic tests with injected clocks and HTTP transport.

The Function code is deployment-ready but is not deployed by repository verification. Azure resource provisioning, configuration, deployment, trigger synchronization, and live smoke testing remain separate operator actions. No remediation is implemented.

## Batch 4 foundation flow

```text
Azure Monitor Action Group (future)
  -> POST /api/alerts/azure-monitor (Function authLevel=function)
  -> validate and normalize
  -> taski-incident-events queue
  -> validate normalized incident again
  -> sign exact request-body bytes
  -> Taski internal incident endpoint
```

The HTTP receiver never calls Taski or OpenAI. Assigning the normalized queue string is its final side effect before returning `202`. The queue processor owns Taski delivery and the guarded Batch 5B AI step.

## Azure Functions model

The project uses the GA `@azure/functions` v4 programming model with code-centric `app.http`, `output.storageQueue`, and `app.storageQueue` registration. `package.json` points the Functions worker to `dist/src/functions/*.js`; no per-function `function.json` files are used. `host.json` selects extension bundle `[4.0.0, 5.0.0)`.

Queue messages are canonical JSON strings. `host.json` sets queue `messageEncoding` to `none`, so the binding stores plain UTF-8 JSON rather than requiring an application-created Base64 envelope. The processor accepts the runtime's JSON-decoded value or the original string and always applies the strict normalized schema before forwarding.

## Local setup

Prerequisites: Node.js 22 or newer and npm.

```powershell
npm.cmd install
npm.cmd run typecheck
npm.cmd run build
npm.cmd run test:run
npm.cmd run --silent replay:alert -- test/fixtures/azure-alert-fired.json
npm.cmd run --silent replay:alert -- test/fixtures/azure-alert-resolved.json
```

Copy `local.settings.example.json` to ignored `local.settings.json` only for future local-host work and replace every placeholder. Do not commit credentials. The build and tests need no real secrets, storage account, Taski endpoint, or network access.

## Configuration

Application-owned runtime settings are validated explicitly at invocation boundaries:

- `AZURE_INCIDENT_QUEUE_NAME` (default documented value: `taski-incident-events`)
- `TASKI_INTERNAL_BASE_URL` (HTTPS, except explicit localhost HTTP; no embedded credentials)
- `TASKI_INCIDENT_KEY_ID`
- `TASKI_INCIDENT_SECRET` (32–4096 UTF-8 bytes)
- `TASKI_REQUEST_TIMEOUT_MS` (default 10000; allowed 1000–30000)

The queue handler validates Taski transport first and persists the incident before consulting triage identity or OpenAI execution settings. Resolved, already-resolved, and stale alerts therefore do not require OpenAI configuration. For an eligible fired alert with a valid policy identity, missing or invalid OpenAI settings produce a bounded `model_unavailable` result for authenticated Taski delivery; raw values and validation details are never included.

The Azure Function key used by a future Action Group authenticates access to the receiver URL. It is separate from the Taski HMAC secret used only by the queue processor. Production hardening should place the webhook behind appropriate Entra protection where practical.

`AzureWebJobsStorage` is a Functions-host connection name, not an application secret contract. Both bindings reference that name, but application code never reads or validates it. Keep the Function App's existing identity-based `AzureWebJobsStorage__*` settings; do not add a plaintext connection string. Local emulation may use an ignored `local.settings.json` value.

## Flex Consumption deployment readiness

The deployment root is this repository root: `host.json` and `package.json` must remain here. `npm.cmd run build` compiles production source only to `dist/src`, and `package.json` discovers both registrations through `dist/src/functions/*.js`. Tests, fixtures, demo/replay scripts, local settings, environment files, documentation, local `node_modules`, and non-runtime compiled files are excluded by `.funcignore`.

For the existing Linux Flex Consumption app, use Azure Functions Core Tools v4 from this root after all checks pass and after an authorized Azure CLI sign-in and subscription selection:

```powershell
func azure functionapp publish taski-ai-triage
```

Do not pass `--publish-local-settings`, `--nozip`, or publish-profile/basic-auth credentials. Core Tools uses the Flex-supported package deployment path and requests a Linux remote build, so Azure installs the lock-file-defined dependencies for the target platform. Verify Node.js 22+, npm, Core Tools v4, and Azure CLI 2.60+ first. Deployment is an operator action and was not run during this audit.

Azure starts the Node worker and loads the `package.json` `main` glob; it does not use `npm start`. For a local Functions host, build first and run `func start` with Core Tools v4. All repository npm scripts use cross-platform Node package executables and contain no Windows-only shell commands.

## Retry behavior

Taski delivery and pipeline failures are thrown. OpenAI failures are converted to a safe failed result, whose Taski delivery must still succeed. A retry skips analysis only for the exact expected terminal identity already accepted by Taski. Azure Queue trigger retry behavior owns redelivery; there is no internal retry loop or exactly-once claim. `host.json` sets `maxDequeueCount` to 5 and a bounded visibility timeout. After the configured attempts, the Functions runtime moves the message to `<queue-name>-poison`. No remediation occurs automatically.

See [architecture](docs/architecture.md), [security](docs/security.md), and the [demo script](docs/demo-script.md).

## License

MIT
