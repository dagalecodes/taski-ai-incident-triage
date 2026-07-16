# Taski AI Incident Triage

Taski AI Incident Triage is a contract-first Azure Monitor incident intake service for Taski. This repository owns alert validation, normalization, queued delivery, and authenticated forwarding; it does not contain or replace the Taski application.

## Batch 4 status

Batch 4 implements a local Azure Functions-compatible queue-first pipeline:

- an Azure Functions Node.js v4 HTTP receiver for Common Alert Schema payloads;
- strict Batch 1 validation and deterministic normalization;
- a Storage Queue output binding containing only the normalized incident;
- a queue-triggered processor that validates the message again;
- exact-byte HMAC-SHA256 signing and bounded Taski HTTP forwarding;
- deterministic tests with injected clocks and HTTP transport.

It has not been deployed. No Azure resources, Function key, Action Group, live queue, OpenAI agent, diagnostic tools, AI diagnosis, Application Insights, or remediation are implemented by this batch.

## Implemented flow

```text
Azure Monitor Action Group (future)
  -> POST /api/alerts/azure-monitor (Function authLevel=function)
  -> validate and normalize
  -> taski-incident-events queue
  -> validate normalized incident again
  -> sign exact request-body bytes
  -> Taski internal incident endpoint
```

The HTTP receiver never calls Taski. Assigning the normalized queue string is the receiver's final side effect before returning `202`. The queue processor is the only Taski caller.

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

Runtime settings are validated explicitly at invocation boundaries:

- `AzureWebJobsStorage`
- `AZURE_INCIDENT_QUEUE_NAME` (default documented value: `taski-incident-events`)
- `TASKI_INTERNAL_BASE_URL` (HTTPS, except explicit localhost HTTP; no embedded credentials)
- `TASKI_INCIDENT_KEY_ID`
- `TASKI_INCIDENT_SECRET` (32–4096 UTF-8 bytes)
- `TASKI_REQUEST_TIMEOUT_MS` (default 10000; allowed 1000–30000)

The Azure Function key used by a future Action Group authenticates access to the receiver URL. It is separate from the Taski HMAC secret used only by the queue processor. Production hardening should place the webhook behind appropriate Entra protection where practical.

## Retry behavior

Processing failures are thrown. Azure Queue trigger retry behavior owns redelivery; there is no internal retry loop. `host.json` sets `maxDequeueCount` to 5 and a bounded visibility timeout. After the configured attempts, the Functions runtime moves the message to `<queue-name>-poison`. No remediation occurs automatically; an operator must inspect safe metadata and correct configuration or code.

See [architecture](docs/architecture.md), [security](docs/security.md), and the [demo script](docs/demo-script.md).

## License

MIT
