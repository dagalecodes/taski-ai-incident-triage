# Security

## Batch 5B AI boundary

Alert strings and diagnostic output are untrusted data, never instructions. Before model input, the worker bounds strings, redacts common tokens/passwords/keys/connection strings, and marks prompt-injection-like text. Raw Azure payloads, `alertContext`, and `customProperties` cannot enter model context.

The five tools use strict empty Zod inputs, current-incident resource scope, injected providers, bounded strict outputs, and safe unavailable fallbacks. They offer no arbitrary resource identifier, URL, query language, filesystem, shell, network client, or write operation. Runbook references remain untrusted evidence text rather than navigation or remediation controls.

The final result is parsed through the existing strict `triageResultSchema`. Evidence must exactly match sanitized tool evidence. Deterministic guards reject executable/command-like actions, SQL/scripts, secrets, fabricated evidence, and unsafe references. Every action remains human-review-only.

The Agents SDK enables tracing in server runtimes, so the worker sets `tracingDisabled` unless `OPENAI_TRACING_ENABLED=true`. Sensitive trace data capture is always disabled. Explicit opt-in may still export workflow and tool operational metadata to OpenAI and therefore requires a privacy assessment. No secrets, raw alerts, raw logs, HMAC values, or Taski bodies are added to trace metadata.

Taski incident and triage bodies are independently serialized once, signed over the exact bytes, and transmitted with redirects disabled, bounded timeouts/responses, and strict response schemas. Incident ingestion requires a bounded nullable analysis ID and exact analysis-status enum. Only an exact expected terminal identity suppresses triage; null, different-policy, and nonterminal identities remain eligible. There is no internal retry or autonomous remediation.

## Trust boundaries

Azure Monitor payloads and queue messages are untrusted. The HTTP receiver validates Common Alert Schema, applies a byte bound, and normalizes to an allowlist. The processor independently validates the queue value before signing or networking.

The future Azure Function key and Taski HMAC secret are different credentials:

- A Function key lets a future Action Group invoke the receiver URL.
- The Taski HMAC secret authenticates the processor's exact request bytes to Taski.
- Neither credential is placed in the queue or repository examples.
- This batch creates neither a Function key nor an Action Group.

An Entra-protected secure webhook should replace or strengthen Function-key-only ingress where appropriate for production.

## Exact-body signing

The processor validates the normalized object, serializes it once, and retains the resulting UTF-8 bytes. It signs:

```text
HMAC-SHA256(secret, UTF8(timestamp) + UTF8(".") + exactBodyBytes)
```

The same `exactBodyBytes` are passed to `fetch`. Secrets must be 32–4096 UTF-8 bytes, timestamps are positive epoch seconds, and signatures are 64 lowercase hexadecimal characters. Redirect following is disabled, the destination forbids embedded credentials, and HTTPS is required except explicit localhost development.

## Queue content and encoding

The output binding receives a canonical JSON string containing only the normalized incident. `host.json` uses Storage Queue extension bundle 4.x and `messageEncoding: none`, matching plain UTF-8 producer content. The processor rejects unknown fields, unsupported schema versions, malformed JSON, and oversized string messages; it does not repair them.

Raw `alertContext`, `customProperties`, provider headers, authorization data, target credentials, Taski signatures, and secrets never enter the queue. Raw Azure payloads never reach Taski.

## Network and response controls

- Exact Taski endpoint path; normalized trailing slash
- HTTPS except localhost HTTP
- No URL credentials, query, or fragment
- Bounded 1–30 second timeout
- `redirect: manual`
- Bounded response body
- Strict 2xx response schema
- Only `created`, `updated`, `duplicate`, and `stale` succeed
- Every successful ingestion response requires safe `analysisId` and `analysisStatus` fields
- 401, 429, 5xx, timeout, network failure, invalid JSON, unknown status, and extra response fields fail safely

No response body, signature, secret, raw alert, normalized body, target resource ID, request headers, or stack trace is logged.

## Retry and poison handling

Processor failures are thrown so the queue delivery is not acknowledged. The Azure Functions queue extension performs retry; no internal loop exists. `maxDequeueCount` is 5. After that, the runtime moves the message to `<queue-name>-poison`. Logging is limited to safe operational identifiers/categories. Operators must inspect safe metadata and fix configuration or code; no remediation is automatic.

An accepted matching terminal identity prevents a retry from recreating a different result after a lost Taski response. It does not provide a distributed claim or lease, so simultaneous duplicate workers may both start paid analysis before either result is accepted. Exactly-once OpenAI execution is not claimed. Missing OpenAI execution configuration is converted, after fired-incident ingestion and stable policy identification, into a safe `model_unavailable` result without raw configuration values. Agents SDK tracing remains disabled by default.

## Remaining hardening

- Deploy and verify Azure resources, RBAC, private networking, and managed identities
- Configure and rotate real Function/HMAC keys outside source control
- Add Entra webhook protection, rate limiting, and operational monitoring
- Add poison-queue operating procedures and privacy-aware telemetry
- Add runtime secret scanning where required
- Connect real allowlisted Azure diagnostic providers in Batch 6
- Validate production model, privacy, tracing, RBAC, and poison-queue operations before deployment

Zod validates shape and bounds; it does not establish that provider content is truthful. Taski remains responsible for participant authorization and durable incident persistence.
