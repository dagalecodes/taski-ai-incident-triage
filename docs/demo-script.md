# Batch 4 demo script

Batch 4 is a local, tested implementation. Do not describe the Azure path as deployed or live.

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

Clearly state that tests inject output bindings, clocks, and HTTP transport. They do not contact Azure or Taski.

## Future live demonstration

A later deployment may connect an Azure Monitor Action Group to the Function URL/key, use a real Storage Queue, and forward to Taski. That requires separately provisioned Azure resources, secrets, RBAC, networking, Taski configuration, and operational verification.

OpenAI diagnosis, diagnostic tools, Application Insights, and remediation are not part of Batch 4. A Batch 5 AI step may run only after incident persistence and must remain read-only and contract-bound.
