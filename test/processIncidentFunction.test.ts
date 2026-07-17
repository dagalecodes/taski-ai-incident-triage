import type { InvocationContext } from '@azure/functions';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { normalizedIncidentSchema } from '../src/contracts/normalizedIncident.js';
import { processIncidentHandler } from '../src/functions/processIncident.js';

const taskiEnvironment = {
  TASKI_INTERNAL_BASE_URL: 'https://taski.example.invalid',
  TASKI_INCIDENT_KEY_ID: 'synthetic-key',
  TASKI_INCIDENT_SECRET: '0123456789abcdef0123456789abcdef',
  TASKI_REQUEST_TIMEOUT_MS: '10000',
};

function message(condition: 'fired' | 'resolved' = 'fired') {
  return normalizedIncidentSchema.parse({
    schemaVersion: 1, provider: 'azure_monitor', externalAlertId: 'synthetic-alert',
    deliveryId: `sha256:${'d'.repeat(64)}`, condition, severity: 'warning',
    alertRule: 'Synthetic rule', affectedService: 'synthetic-service',
    targetResourceId: '/subscriptions/000/resourceGroups/demo/providers/Microsoft.Web/sites/synthetic',
    signalType: 'Metric', monitoringService: 'Platform', summary: 'Synthetic incident.',
    occurredAt: condition === 'fired' ? '2026-07-15T08:00:00.000Z' : '2026-07-15T08:06:30.000Z',
    receivedAt: '2026-07-16T10:00:00.000Z',
  });
}

function context(): InvocationContext {
  return { info: vi.fn(), error: vi.fn() } as unknown as InvocationContext;
}

function stubEnvironment(values: Record<string, string>): void {
  for (const [name, value] of Object.entries({ ...taskiEnvironment, ...values })) vi.stubEnv(name, value);
}

function ingestionResponse(overrides: Record<string, unknown> = {}) {
  return {
    status: 'created', incidentId: 7, messageId: 12, alertState: 'fired',
    analysisId: null, analysisStatus: 'pending', version: 1, ...overrides,
  };
}

function taskiFetch(response: Record<string, unknown>) {
  return vi.fn(async (input: Parameters<typeof fetch>[0], _init?: Parameters<typeof fetch>[1]) => {
    if (String(input).endsWith('/azure-monitor')) {
      return new Response(JSON.stringify(response), { status: response.status === 'created' ? 201 : 200 });
    }
    return new Response(JSON.stringify({
      status: 'updated', incidentId: 7, messageId: 12, alertState: 'fired',
      analysisStatus: 'failed', version: 2,
    }), { status: 200 });
  });
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe('Azure queue handler configuration ordering', () => {
  it.each([
    ['resolved alert', message('resolved'), ingestionResponse({
      status: 'updated', alertState: 'resolved', analysisStatus: 'not_required', version: 2,
    })],
    ['stale fired alert', message(), ingestionResponse({ status: 'stale', version: 2 })],
    ['already-resolved fired retry', message(), ingestionResponse({
      status: 'duplicate', alertState: 'resolved', analysisStatus: 'not_required', version: 2,
    })],
  ])('%s succeeds without valid OpenAI or policy configuration', async (_name, incident, response) => {
    stubEnvironment({
      OPENAI_API_KEY: '', OPENAI_MODEL: 'bad model', OPENAI_MAX_TURNS: 'invalid',
      OPENAI_TRACING_ENABLED: 'invalid', TRIAGE_POLICY_VERSION: 'bad policy',
    });
    const fetchImplementation = taskiFetch(response);
    vi.stubGlobal('fetch', fetchImplementation);
    await expect(processIncidentHandler(incident, context())).resolves.toBeUndefined();
    expect(fetchImplementation).toHaveBeenCalledOnce();
    expect(String(fetchImplementation.mock.calls[0]?.[0])).toMatch(/\/azure-monitor$/);
  });

  it('ingests fired incident before missing OpenAI configuration and sends a safe failed result', async () => {
    stubEnvironment({
      TRIAGE_POLICY_VERSION: 'policy-v1', OPENAI_API_KEY: '', OPENAI_MODEL: 'raw invalid model value',
      OPENAI_REQUEST_TIMEOUT_MS: 'private-invalid-timeout', OPENAI_MAX_TURNS: 'private-invalid-turns',
      OPENAI_TRACING_ENABLED: 'private-invalid-tracing',
    });
    const fetchImplementation = taskiFetch(ingestionResponse());
    vi.stubGlobal('fetch', fetchImplementation);
    await expect(processIncidentHandler(message(), context())).resolves.toBeUndefined();
    expect(fetchImplementation).toHaveBeenCalledTimes(2);
    expect(String(fetchImplementation.mock.calls[0]?.[0])).toMatch(/\/azure-monitor$/);
    expect(String(fetchImplementation.mock.calls[1]?.[0])).toMatch(/\/triage-results$/);
    const sent = JSON.parse(Buffer.from(
      fetchImplementation.mock.calls[1]?.[1]?.body as Uint8Array,
    ).toString('utf8')) as Record<string, unknown>;
    expect(sent).toMatchObject({
      analysisStatus: 'failed', diagnosis: null, failure: { code: 'model_unavailable' },
    });
    expect(JSON.stringify(sent)).not.toMatch(/raw invalid|private-invalid|OPENAI_/);
  });

  it('fails invalid policy safely only after fired incident ingestion', async () => {
    stubEnvironment({
      TRIAGE_POLICY_VERSION: 'bad policy', OPENAI_API_KEY: '', OPENAI_MODEL: '',
    });
    const fetchImplementation = taskiFetch(ingestionResponse());
    vi.stubGlobal('fetch', fetchImplementation);
    await expect(processIncidentHandler(message(), context())).rejects.toThrow('configuration');
    expect(fetchImplementation).toHaveBeenCalledOnce();
    expect(String(fetchImplementation.mock.calls[0]?.[0])).toMatch(/\/azure-monitor$/);
  });
});
