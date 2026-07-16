# Taski AI Incident Triage

Taski AI Incident Triage is a contract-first incident intake and triage service being built for Taski. It targets the gap between an Azure Monitor alert firing and a team receiving a persistent, evidence-backed, human-actionable incident inside its collaboration workflow.

Taski is an existing collaboration product. This public repository contains the new Azure ingestion and incident-triage service; it does not contain or replace the Taski application source.

## Batch 1 status

This batch implements only the local project foundation:

- strict Azure Monitor Common Alert Schema validation;
- a smaller normalized incident contract;
- deterministic delivery IDs for future idempotency;
- a strict future triage-result contract;
- explicit future configuration validation;
- sanitized fired, resolved, duplicate, malicious, and invalid fixtures;
- a local replay command and automated tests.

It does **not** implement a webhook, Azure Function, queue, agent, OpenAI call, Taski API/UI integration, database, deployment, or automatic remediation. No live Azure, OpenAI, queue, or Taski integration is claimed to work in Batch 1.

## Target architecture

```text
Azure Monitor → authenticated receiver → durable queue → read-only triage worker
      → normalized incident/result → Taski group incident card → human approval
```

Taski remains the collaboration, authorization, persistence, and UI system. This repository will own Azure alert intake, normalization, queued triage, and authenticated delivery of safe results in later batches. See [architecture](docs/architecture.md), [security](docs/security.md), and the [target demo](docs/demo-script.md).

## Local setup

Prerequisites: Node.js 22 or newer and npm.

```powershell
npm.cmd install
npm.cmd run typecheck
npm.cmd run build
npm.cmd run test:run
npm.cmd run --silent replay:alert -- test/fixtures/azure-alert-fired.json
```

Other commands:

```powershell
npm.cmd test
npm.cmd run --silent replay:alert -- test/fixtures/azure-alert-resolved.json
```

The replay command reads one local file, validates and normalizes it, writes normalized JSON to standard output, and makes no network request. Invalid input exits nonzero with a concise error.

## Safety boundary

- Raw `alertContext` and `customProperties` are validated only as bounded provider input and never copied into normalized incidents.
- Displayable fields and arrays are bounded.
- Triage output is strict and contains no command, script, tool-argument, chain-of-thought, or auto-remediation field.
- Every recommended action requires human approval.
- `.env.example` contains placeholders only; ordinary builds and tests require no credentials.
- Schema validation does not itself detect secrets. Runtime redaction, webhook authentication, replay persistence, queue controls, tool allowlists, and safe logging remain later work.

## License

MIT
