# Security

## Threat model

Alert payloads are untrusted input. Threats include forged webhooks, replayed or duplicate deliveries, oversized payloads, prompt injection hidden in provider context, fake secrets, sensitive logs, unsafe tool arguments, and attempts to turn recommendations into automatic remediation.

## Controls implemented in Batch 1

- Exact Common Alert Schema identifier and required essentials validation
- Case-insensitive fired/resolved validation with unsupported conditions rejected
- Exact severity allowlist and deterministic severity mapping
- Valid timezone-bearing ISO-8601 timestamps
- Required target resource and resolved timestamp invariants
- Maximum lengths, array counts, provider-object size, and replay-file size
- Bounded provider passthrough for alert-type compatibility
- Deliberately smaller normalized output
- No propagation of raw `alertContext` or `customProperties`
- Deterministic canonical digest for future duplicate detection
- Strict triage objects with unknown fields rejected
- No command, script, executable payload, tool arguments, chain-of-thought, raw-log, or remediation-result field
- Literal `requiresHumanApproval: true` on every recommended action
- Configuration validation only when explicitly called
- Safe configuration errors that name fields but never values
- Replay failures do not print rejected payloads or stack traces
- Synthetic fixtures only

The malicious fixture demonstrates containment, not secret detection: injection text and fake credentials placed in ignored provider fields do not enter normalized output.

## Deferred controls

- Azure receiver authentication or Entra protection
- HMAC body signatures, timestamp windows, nonce storage, and key rotation
- Durable idempotency and fired/resolved transaction handling
- Queue access control, poison-message handling, and bounded retries
- Runtime secret scanning and redaction
- Approved diagnostic-tool allowlists and resource scoping
- Prompt construction and prompt-injection isolation
- OpenAI response parsing and model-call timeouts
- Taski service authentication and backend authorization
- Structured privacy-aware logging, correlation IDs, metrics, and tracing
- Rate limiting and HTTP body limits at the receiver
- Dependency and deployment security scanning

## Honest limitations

Zod validates shape, bounds, and allowlists; it does not prove content is truthful or secret-free. A deterministic delivery ID is not replay protection until a trusted persistent store enforces uniqueness. Human-approval fields are a contract, not an authorization system. Those controls must be enforced by later runtime components and Taski.
