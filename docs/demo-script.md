# Batch 5B demo script

Batch 5B is a local, deterministic demonstration. Do not describe OpenAI, Azure, Taski, queues, or diagnostic providers as live or deployed.

Show that:

1. Resolved and stale incidents update Taski state but skip AI.
2. Fired `created`, `updated`, and `duplicate` responses run triage unless Taski returns the exact expected terminal analysis identity.
3. The one Agent uses the existing Batch 1 Zod schema as structured output.
4. All five strict read-only tools use injected sanitized fixtures and current-incident scope.
5. Redaction, prompt-injection marking, evidence-ledger enforcement, command rejection, and safe failed results are deterministic.
6. Exact signed bytes equal transmitted bytes for both Taski endpoints.
7. Taski result-delivery failure throws for Azure Queue retry/poison behavior.
8. Tracing defaults to disabled and no test exports traces or calls a real network.
9. A lost-response retry skips a matching accepted result, while null, changed-policy, and nonterminal identities remain eligible.

The current runtime diagnostic provider reports unavailable. Real Azure Monitor diagnostic providers, RBAC, privacy validation, deployment, and operational monitoring are Batch 6 work. No remediation or clickable runbook action exists.

The Batch 4 receiver and queue foundation remains part of this local Batch 5B demonstration.

## Network-free demonstration

1. Show `src/functions/receiveAzureAlert.ts` registering a function-authenticated POST receiver.
2. Run the fired and resolved replay commands to demonstrate unchanged Batch 1 normalization.
3. Show tests proving the receiver assigns only normalized canonical JSON to its queue output.
4. Show tests proving the processor validates again and signs the exact bytes sent to Taski.
5. Show tests for `created`, `updated`, `duplicate`, `stale`, timeout, network, authentication, rate-limit, server, and malformed-response handling.
6. Show `host.json`: plain message encoding, five dequeue attempts, and poison-queue behavior.

```powershell
npm.cmd run typecheck
npm.cmd run build
npm.cmd run test:run
npm.cmd run --silent replay:alert -- test/fixtures/azure-alert-fired.json
npm.cmd run --silent replay:alert -- test/fixtures/azure-alert-resolved.json
```

Clearly state that tests inject output bindings, clocks, model runner, diagnostic providers, and HTTP transport. They do not contact OpenAI, Azure, Taski, or any telemetry system.

Also state that the identity check is retry recovery, not a distributed claim or lease. Simultaneous duplicate workers may both begin analysis before either result is accepted, and exactly-once OpenAI execution is not claimed.

## Future live demonstration

A later deployment may connect an Azure Monitor Action Group to the Function URL/key, use a real Storage Queue, and forward to Taski. That requires separately provisioned Azure resources, secrets, RBAC, networking, Taski configuration, and operational verification.

Batch 6 may connect real read-only Azure diagnostic providers after separate RBAC, privacy, and deployment review. Application Insights and remediation are not implemented.
