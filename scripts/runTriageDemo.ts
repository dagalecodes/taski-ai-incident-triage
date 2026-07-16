import { readFile, stat } from 'node:fs/promises';
import { extname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createOpenAITriageRunner, SafeTriageError, type TriageRunner } from '../src/agent/triageAgent.js';
import { normalizeAzureAlert } from '../src/alerts/normalizeAzureAlert.js';
import {
  validateOpenAIEnvironment,
  validateTaskiEnvironment,
  validateTriageIdentityEnvironment,
} from '../src/config/env.js';
import { azureMonitorCommonAlertSchema } from '../src/contracts/azureMonitor.js';
import type { NormalizedIncident } from '../src/contracts/normalizedIncident.js';
import type { TriageResult } from '../src/contracts/triageResult.js';
import { createUnavailableDiagnosticProvider } from '../src/diagnostics/tools.js';
import { deterministicAnalysisId, processIncident } from '../src/pipeline/processIncident.js';
import { validateGuardedTriageResult } from '../src/security/triageGuardrails.js';

const MAX_FIXTURE_BYTES = 256 * 1024;
const DEFAULT_FIRED_FIXTURE = 'test/fixtures/azure-alert-fired.json';
const DEFAULT_RESOLVED_FIXTURE = 'test/fixtures/azure-alert-resolved.json';
const DRY_RUN_POLICY = 'batch-5c-dry-run-v1';
const LOCALHOST_PORTS = new Set(['3000']);

export type DemoScenario =
  | 'created'
  | 'duplicate-terminal'
  | 'resolved'
  | 'stale'
  | 'model-failure'
  | 'result-delivery-failure';

export type DemoMode = 'dry-run' | 'deterministic-staging' | 'openai-staging';

interface DemoOptions {
  fixturePath: string;
  mode: DemoMode;
  scenario: DemoScenario;
}

export interface TriageDemoDependencies {
  readTextFile(path: string): Promise<string>;
  environment: Readonly<Record<string, string | undefined>>;
  fetchImplementation: typeof fetch;
  currentTimestamp(): string;
  currentEpochSeconds(): number;
  currentIsoTimestamp(): string;
  writeOutput(value: string): void;
  writeError(value: string): void;
}

export interface SafeDemoSummary {
  mode: DemoMode;
  scenario: DemoScenario;
  condition: NormalizedIncident['condition'];
  externalAlertId: string;
  deliveryId: string;
  incidentStatus: 'created' | 'updated' | 'duplicate' | 'stale';
  incidentId: number;
  triage: 'ran' | 'skipped';
  triageDeliveryStatus: 'updated' | 'duplicate' | 'stale' | null;
  analysisStatus: 'pending' | 'queued' | 'investigating' | 'ready' | 'failed' | 'not_required' | 'completed';
  analysisId: string | null;
}

function runtimeDependencies(): TriageDemoDependencies {
  return {
    async readTextFile(path) {
      if (extname(path).toLowerCase() !== '.json') throw new Error('Fixture must be JSON.');
      const fileStats = await stat(path);
      if (!fileStats.isFile() || fileStats.size === 0 || fileStats.size > MAX_FIXTURE_BYTES) {
        throw new Error('Fixture must be a bounded regular file.');
      }
      return readFile(path, 'utf8');
    },
    environment: process.env,
    fetchImplementation: fetch,
    currentTimestamp: () => new Date().toISOString(),
    currentEpochSeconds: () => Math.floor(Date.now() / 1_000),
    currentIsoTimestamp: () => new Date().toISOString(),
    writeOutput: (value) => process.stdout.write(value),
    writeError: (value) => process.stderr.write(value),
  };
}

function optionValue(arguments_: readonly string[], index: number): string {
  const value = arguments_[index + 1];
  if (!value || value.startsWith('--')) throw new Error('Missing option value.');
  return value;
}

export function parseDemoArguments(arguments_: readonly string[]): DemoOptions {
  let fixturePath: string | undefined;
  let scenario: DemoScenario = 'created';
  let scenarioExplicit = false;
  let deliverStaging = false;
  let confirmStaging = false;
  let useOpenAI = false;
  let confirmCharge = false;
  const scenarios = new Set<DemoScenario>([
    'created', 'duplicate-terminal', 'resolved', 'stale', 'model-failure', 'result-delivery-failure',
  ]);

  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === '--fixture') {
      fixturePath = optionValue(arguments_, index);
      index += 1;
    } else if (argument === '--scenario') {
      const value = optionValue(arguments_, index) as DemoScenario;
      if (!scenarios.has(value)) throw new Error('Unknown scenario.');
      scenario = value;
      scenarioExplicit = true;
      index += 1;
    } else if (argument === '--deliver-staging') deliverStaging = true;
    else if (argument === '--confirm-staging-delivery') confirmStaging = true;
    else if (argument === '--use-openai') useOpenAI = true;
    else if (argument === '--confirm-openai-charge') confirmCharge = true;
    else throw new Error('Unknown option.');
  }

  if (confirmStaging && !deliverStaging) throw new Error('Conflicting delivery confirmation.');
  if (useOpenAI && (!deliverStaging || !confirmStaging || !confirmCharge)) {
    throw new Error('OpenAI mode is not fully confirmed.');
  }
  if (confirmCharge && !useOpenAI) throw new Error('Conflicting OpenAI confirmation.');
  if (deliverStaging && !confirmStaging) throw new Error('Staging delivery is not confirmed.');
  if (deliverStaging && scenarioExplicit) throw new Error('Dry-run scenarios cannot be delivered.');

  const mode: DemoMode = useOpenAI
    ? 'openai-staging'
    : (deliverStaging ? 'deterministic-staging' : 'dry-run');
  const selectedFixture = fixturePath
    ?? (scenario === 'resolved' ? DEFAULT_RESOLVED_FIXTURE : DEFAULT_FIRED_FIXTURE);
  return { fixturePath: selectedFixture, mode, scenario };
}

export function validateStagingTaskiUrl(value: string): string {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash || !['', '/'].includes(url.pathname)) {
    throw new Error('Unsafe Taski staging URL.');
  }
  const staging = url.protocol === 'https:'
    && url.hostname === 'taski-staging.azurewebsites.net' && url.port === '';
  const localhost = url.protocol === 'http:'
    && url.hostname === 'localhost' && LOCALHOST_PORTS.has(url.port);
  if (!staging && !localhost) throw new Error('Unsafe Taski staging URL.');
  return url.toString().replace(/\/$/, '');
}

export function deterministicFallbackTriage(): TriageResult {
  return validateGuardedTriageResult({
    schemaVersion: 1,
    classification: 'unknown',
    probableCause: 'Based only on the alert fixture, an availability issue may be present; root cause is not confirmed.',
    confidence: 0.35,
    evidence: [],
    recommendedActions: [{
      action: 'Have an authorized operator review the incident and validate current service health.',
      requiresHumanApproval: true,
    }],
    limitations: ['Live telemetry and OpenAI analysis were not used.'],
  }, []);
}

function deterministicRunner(scenario: DemoScenario): TriageRunner {
  if (scenario === 'model-failure') {
    return { async run() { throw new SafeTriageError('model_unavailable'); } };
  }
  return { async run() { return deterministicFallbackTriage(); } };
}

function dryRunFetch(scenario: DemoScenario, expectedAnalysisId: string): typeof fetch {
  return async (input) => {
    const url = String(input);
    if (url.endsWith('/azure-monitor')) {
      const response = scenario === 'duplicate-terminal'
        ? {
            status: 'duplicate', incidentId: 7001, messageId: 8001, alertState: 'fired',
            analysisId: expectedAnalysisId, analysisStatus: 'ready', version: 2,
          }
        : scenario === 'resolved'
          ? {
              status: 'updated', incidentId: 7001, messageId: 8001, alertState: 'resolved',
              analysisId: null, analysisStatus: 'not_required', version: 2,
            }
          : scenario === 'stale'
            ? {
                status: 'stale', incidentId: 7001, messageId: 8001, alertState: 'fired',
                analysisId: null, analysisStatus: 'pending', version: 2,
              }
            : {
                status: 'created', incidentId: 7001, messageId: 8001, alertState: 'fired',
                analysisId: null, analysisStatus: 'pending', version: 1,
              };
      return new Response(JSON.stringify(response), { status: response.status === 'created' ? 201 : 200 });
    }
    if (scenario === 'result-delivery-failure') {
      return new Response('simulated private failure', { status: 503 });
    }
    return new Response(JSON.stringify({
      status: 'updated', incidentId: 7001, messageId: 8001, alertState: 'fired',
      analysisStatus: scenario === 'model-failure' ? 'failed' : 'ready', version: 2,
    }), { status: 200 });
  };
}

async function normalizedFixture(
  options: DemoOptions,
  dependencies: TriageDemoDependencies,
): Promise<NormalizedIncident> {
  let fixtureText = await dependencies.readTextFile(resolve(options.fixturePath));
  if (Buffer.byteLength(fixtureText, 'utf8') > MAX_FIXTURE_BYTES) throw new Error('Fixture is too large.');
  let payload: unknown;
  try {
    payload = JSON.parse(fixtureText);
  } finally {
    fixtureText = '';
  }
  const validated = azureMonitorCommonAlertSchema.parse(payload);
  const normalized = normalizeAzureAlert(validated, dependencies.currentTimestamp());
  if (options.scenario === 'resolved' && normalized.condition !== 'resolved') {
    throw new Error('Resolved scenario requires a resolved fixture.');
  }
  return normalized;
}

async function executeDemo(
  options: DemoOptions,
  dependencies: TriageDemoDependencies,
): Promise<SafeDemoSummary> {
  const incident = await normalizedFixture(options, dependencies);
  let taskiBaseUrl = 'https://taski.example.invalid';
  let keyId = 'dry-run-key';
  let secret = 'dry-run-secret-0123456789abcdef0';
  let timeoutMs = 10_000;
  let policyVersion = DRY_RUN_POLICY;
  let fetchImplementation: typeof fetch;
  let createTriageRunner: () => TriageRunner;

  if (options.mode === 'dry-run') {
    const expectedId = deterministicAnalysisId(incident, policyVersion);
    fetchImplementation = dryRunFetch(options.scenario, expectedId);
    createTriageRunner = () => deterministicRunner(options.scenario);
  } else {
    const taski = validateTaskiEnvironment(dependencies.environment);
    const identity = validateTriageIdentityEnvironment(dependencies.environment);
    taskiBaseUrl = validateStagingTaskiUrl(taski.TASKI_INTERNAL_BASE_URL);
    keyId = taski.TASKI_INCIDENT_KEY_ID;
    secret = taski.TASKI_INCIDENT_SECRET;
    timeoutMs = taski.TASKI_REQUEST_TIMEOUT_MS;
    policyVersion = identity.TRIAGE_POLICY_VERSION;
    fetchImplementation = dependencies.fetchImplementation;
    if (options.mode === 'openai-staging') {
      const openAI = validateOpenAIEnvironment(dependencies.environment);
      createTriageRunner = () => createOpenAITriageRunner({
        apiKey: openAI.OPENAI_API_KEY,
        model: openAI.OPENAI_MODEL,
        timeoutMs: openAI.OPENAI_REQUEST_TIMEOUT_MS,
        maxTurns: openAI.OPENAI_MAX_TURNS,
        tracingEnabled: openAI.OPENAI_TRACING_ENABLED,
      }, createUnavailableDiagnosticProvider());
    } else {
      createTriageRunner = () => deterministicRunner(options.scenario);
    }
  }

  try {
    const processed = await processIncident(incident, {
      taskiBaseUrl, keyId, secret, timeoutMs,
    }, {
      fetchImplementation,
      currentEpochSeconds: dependencies.currentEpochSeconds,
      currentIsoTimestamp: dependencies.currentIsoTimestamp,
      resolveTriagePolicyVersion: () => policyVersion,
      createTriageRunner,
    });
    return {
      mode: options.mode,
      scenario: options.scenario,
      condition: processed.incident.condition,
      externalAlertId: processed.incident.externalAlertId,
      deliveryId: processed.incident.deliveryId,
      incidentStatus: processed.result.status,
      incidentId: processed.result.incidentId,
      triage: processed.triageResult ? 'ran' : 'skipped',
      triageDeliveryStatus: processed.triageDelivery?.status ?? null,
      analysisStatus: processed.triageResult?.analysisStatus ?? processed.result.analysisStatus,
      analysisId: processed.triageResult?.analysisId ?? processed.result.analysisId,
    };
  } finally {
    keyId = '';
    secret = '';
  }
}

export async function runTriageDemo(
  arguments_: readonly string[],
  dependencies: TriageDemoDependencies = runtimeDependencies(),
): Promise<number> {
  try {
    const options = parseDemoArguments(arguments_);
    const summary = await executeDemo(options, dependencies);
    dependencies.writeOutput(`${JSON.stringify(summary)}\n`);
    return 0;
  } catch {
    dependencies.writeError('Triage demo failed safely.\n');
    return 1;
  }
}

const isMainModule = process.argv[1] !== undefined
  && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMainModule) process.exitCode = await runTriageDemo(process.argv.slice(2));
