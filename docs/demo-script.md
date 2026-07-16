# Target two-minute demo script

This is the intended demo after later batches land. Batch 1 currently supports only the deterministic local replay fallback.

## Full live path

1. Show the disposable demo API healthy and the designated Taski group open.
2. Make the demo API unhealthy.
3. Azure Monitor detects the failure and sends Common Alert Schema to the authenticated receiver.
4. The receiver validates, normalizes, deduplicates, creates the initial incident, and queues triage.
5. The Taski card progresses from Alert received to Investigating without blocking normal messages.
6. The read-only worker returns bounded evidence, probable cause, confidence, and recommended human actions.
7. A participant acknowledges the incident and explicitly approves Create Task.
8. Restore the demo API; the resolved Azure event updates the same incident.

Do not present this live path as implemented until its receiver, queue, worker, Taski integration, and Azure resources are complete and verified.

## Simulated Azure alert fallback

If live alert delivery is unavailable in a later batch, submit the sanitized fired and resolved fixtures through the same authenticated receiver. Clearly label the input as simulated while preserving the production validation and queue path.

## Batch 1 deterministic replay fallback

Run locally:

```powershell
npm.cmd run --silent replay:alert -- test/fixtures/azure-alert-fired.json
npm.cmd run --silent replay:alert -- test/fixtures/azure-alert-resolved.json
```

Explain that the command performs local parsing, validation, normalization, and deterministic delivery-ID generation only. It does not contact Azure, OpenAI, Taski, or a queue. Show that the reordered duplicate fixture produces the fired delivery ID and that invalid input exits nonzero.
