import { createHmac } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { SafeTriageError, type TriageRunner } from '../src/agent/triageAgent.js';
import { normalizedIncidentSchema, type NormalizedIncident } from '../src/contracts/normalizedIncident.js';
import type { TriageResult } from '../src/contracts/triageResult.js';
import { deterministicAnalysisId, processIncident } from '../src/pipeline/processIncident.js';

function incident(condition: 'fired' | 'resolved' = 'fired'): NormalizedIncident {
  return normalizedIncidentSchema.parse({
    schemaVersion: 1, provider: 'azure_monitor', externalAlertId: 'synthetic-alert',
    deliveryId: `sha256:${'c'.repeat(64)}`, condition,
    severity: condition === 'fired' ? 'warning' : 'informational',
    alertRule: 'Synthetic rule', affectedService: 'synthetic-service',
    targetResourceId: '/subscriptions/000/resourceGroups/demo/providers/Microsoft.Web/sites/synthetic',
    signalType: 'Metric', monitoringService: 'Platform', summary: 'Synthetic incident.',
    occurredAt: condition === 'fired' ? '2026-07-15T08:00:00.000Z' : '2026-07-15T08:06:30.000Z',
    receivedAt: '2026-07-16T10:00:00.000Z',
  });
}

const secret = '0123456789abcdef0123456789abcdef';
const config = {
  taskiBaseUrl: 'https://taski.example.invalid', keyId: 'synthetic-key', secret,
  timeoutMs: 10_000,
};
const diagnosis: TriageResult = {
  schemaVersion: 1, classification: 'performance', probableCause: 'Synthetic CPU pressure.',
  confidence: 0.6,
  evidence: [{ source: 'resource_metrics', finding: 'Synthetic CPU exceeded the fixture threshold.' }],
  recommendedActions: [{ action: 'Review the synthetic capacity plan.', requiresHumanApproval: true }],
  limitations: ['Only deterministic fixture data was available.'],
};

function runner(result: TriageResult = diagnosis): TriageRunner {
  return { run: vi.fn(async () => result) };
}

function taskiFetch(
  status: 'created' | 'updated' | 'duplicate' | 'stale',
  condition: 'fired' | 'resolved' = 'fired',
  analysisId: string | null = null,
  analysisStatus: 'pending' | 'queued' | 'investigating' | 'ready' | 'failed' | 'not_required'
    = condition === 'resolved' ? 'not_required' : 'pending',
) {
  return vi.fn(async (input: Parameters<typeof fetch>[0], _init?: Parameters<typeof fetch>[1]) => {
    const url = String(input);
    if (url.endsWith('/azure-monitor')) {
      return new Response(JSON.stringify({
        status, incidentId: 7, messageId: 12, alertState: condition,
        analysisId, analysisStatus, version: 2,
      }), { status: status === 'created' ? 201 : 200 });
    }
    return new Response(JSON.stringify({
      status: 'updated', incidentId: 7, messageId: 12, alertState: condition,
      analysisStatus: condition === 'resolved' ? 'not_required' : 'ready', version: 3,
    }), { status: 200 });
  });
}

function dependencies(
  fetchImplementation: ReturnType<typeof taskiFetch>,
  triageRunner?: TriageRunner,
  policyVersion = 'policy-v1',
) {
  return {
    fetchImplementation: fetchImplementation as unknown as typeof fetch,
    currentEpochSeconds: () => 1_752_659_200,
    currentIsoTimestamp: () => '2026-07-16T10:01:00.000Z',
    resolveTriagePolicyVersion: () => policyVersion,
    ...(triageRunner ? { createTriageRunner: () => triageRunner } : {}),
  };
}

describe('AI-assisted incident queue processor', () => {
  it('updates Taski for resolved incidents and skips OpenAI', async () => {
    const model = runner();
    const fetchImplementation = taskiFetch('updated', 'resolved');
    const processed = await processIncident(incident('resolved'), config, dependencies(fetchImplementation, model));
    expect(processed.triageResult).toBeUndefined();
    expect(model.run).not.toHaveBeenCalled();
    expect(fetchImplementation).toHaveBeenCalledOnce();
  });

  it('skips OpenAI for stale fired incidents', async () => {
    const model = runner();
    const fetchImplementation = taskiFetch('stale');
    await processIncident(incident(), config, dependencies(fetchImplementation, model));
    expect(model.run).not.toHaveBeenCalled();
    expect(fetchImplementation).toHaveBeenCalledOnce();
  });

  it('skips OpenAI when a fired retry discovers Taski is already resolved', async () => {
    const model = runner();
    const fetchImplementation = vi.fn(async () => new Response(JSON.stringify({
      status: 'duplicate', incidentId: 7, messageId: 12, alertState: 'resolved',
      analysisId: null, analysisStatus: 'not_required', version: 3,
    }), { status: 200 }));
    const processed = await processIncident(incident(), config, dependencies(
      fetchImplementation as unknown as ReturnType<typeof taskiFetch>, model,
    ));
    expect(processed.triageResult).toBeUndefined();
    expect(model.run).not.toHaveBeenCalled();
    expect(fetchImplementation).toHaveBeenCalledOnce();
  });

  it.each(['created', 'updated', 'duplicate'] as const)('runs triage for fired %s ingestion', async status => {
    const model = runner();
    const fetchImplementation = taskiFetch(status);
    const processed = await processIncident(incident(), config, dependencies(fetchImplementation, model));
    expect(model.run).toHaveBeenCalledOnce();
    expect(fetchImplementation).toHaveBeenCalledTimes(2);
    expect(processed.triageResult).toMatchObject({ analysisStatus: 'completed', diagnosis });
    expect(String(fetchImplementation.mock.calls[1]?.[0]).endsWith('/api/incidents/integrations/triage-results')).toBe(true);
  });

  it.each(['ready', 'failed', 'not_required'] as const)(
    'skips paid triage and result delivery for matching terminal %s identity',
    async analysisStatus => {
      const model = runner();
      const analysisId = deterministicAnalysisId(incident(), 'policy-v1');
      const fetchImplementation = taskiFetch('duplicate', 'fired', analysisId, analysisStatus);
      const processed = await processIncident(incident(), config, dependencies(fetchImplementation, model));
      expect(processed.triageResult).toBeUndefined();
      expect(model.run).not.toHaveBeenCalled();
      expect(fetchImplementation).toHaveBeenCalledOnce();
    },
  );

  it('does not suppress a terminal result from a different policy identity', async () => {
    const model = runner();
    const previousId = deterministicAnalysisId(incident(), 'policy-v0');
    const fetchImplementation = taskiFetch('duplicate', 'fired', previousId, 'ready');
    await processIncident(incident(), config, dependencies(fetchImplementation, model, 'policy-v1'));
    expect(model.run).toHaveBeenCalledOnce();
    expect(fetchImplementation).toHaveBeenCalledTimes(2);
  });

  it('does not falsely suppress a matching nonterminal identity', async () => {
    const model = runner();
    const analysisId = deterministicAnalysisId(incident(), 'policy-v1');
    const fetchImplementation = taskiFetch('duplicate', 'fired', analysisId, 'pending');
    await processIncident(incident(), config, dependencies(fetchImplementation, model));
    expect(model.run).toHaveBeenCalledOnce();
    expect(fetchImplementation).toHaveBeenCalledTimes(2);
  });

  it('derives deterministic policy-bound analysis IDs', () => {
    const first = deterministicAnalysisId(incident(), 'policy-v1');
    expect(deterministicAnalysisId(incident(), 'policy-v1')).toBe(first);
    expect(deterministicAnalysisId(incident(), 'policy-v2')).not.toBe(first);
    expect(first).toMatch(/^analysis:policy-v1:[a-f0-9]{64}$/);
  });

  it('sends the same exact triage bytes used by the HMAC', async () => {
    const fetchImplementation = taskiFetch('created');
    await processIncident(incident(), config, dependencies(fetchImplementation, runner()));
    const init = fetchImplementation.mock.calls[1]?.[1];
    const sentBytes = Buffer.from(init?.body as Uint8Array);
    const expected = createHmac('sha256', Buffer.from(secret, 'utf8'))
      .update(Buffer.from('1752659200.', 'utf8')).update(sentBytes).digest('hex');
    expect((init?.headers as Record<string, string>)['X-Taski-Signature']).toBe(expected);
    expect(JSON.parse(sentBytes.toString('utf8'))).toMatchObject({
      analysisStatus: 'completed', diagnosis, sourceDeliveryId: incident().deliveryId,
    });
  });

  it.each([
    ['timeout', new SafeTriageError('timeout'), 'timeout'],
    ['model refusal', new SafeTriageError('invalid_result'), 'invalid_result'],
    ['invalid output', null, 'invalid_result'],
  ] as const)('sends a safe failed result for %s', async (_name, failure, expectedCode) => {
    const model: TriageRunner = failure
      ? { run: vi.fn(async () => { throw failure; }) }
      : { run: vi.fn(async () => ({ rawProviderError: 'private detail' }) as never) };
    const fetchImplementation = taskiFetch('created');
    const processed = await processIncident(incident(), config, dependencies(fetchImplementation, model));
    expect(processed.triageResult).toMatchObject({
      analysisStatus: 'failed', diagnosis: null, failure: { code: expectedCode },
    });
    expect(JSON.stringify(processed.triageResult)).not.toContain('private detail');
  });

  it('sends model_unavailable after ingestion when runner configuration is unavailable', async () => {
    const fetchImplementation = taskiFetch('created');
    const processed = await processIncident(incident(), config, dependencies(fetchImplementation));
    expect(processed.triageResult).toMatchObject({
      analysisStatus: 'failed', diagnosis: null, failure: { code: 'model_unavailable' },
    });
    expect(fetchImplementation).toHaveBeenCalledTimes(2);
  });

  it('fails invalid policy identity only after incident ingestion', async () => {
    const fetchImplementation = taskiFetch('created');
    await expect(processIncident(
      incident(), config, dependencies(fetchImplementation, runner(), 'bad policy'),
    )).rejects.toThrow('configuration');
    expect(fetchImplementation).toHaveBeenCalledOnce();
  });

  it('throws when triage-result delivery fails and has no internal retry loop', async () => {
    const fetchImplementation = vi.fn(async (input: Parameters<typeof fetch>[0]) => {
      if (String(input).endsWith('/azure-monitor')) {
        return new Response(JSON.stringify({
          status: 'duplicate', incidentId: 7, messageId: 12, alertState: 'fired',
          analysisId: null, analysisStatus: 'pending', version: 2,
        }), { status: 200 });
      }
      return new Response('private failure', { status: 503 });
    });
    await expect(processIncident(incident(), config, dependencies(
      fetchImplementation as unknown as ReturnType<typeof taskiFetch>, runner(),
    ))).rejects.toThrow('remote');
    expect(fetchImplementation).toHaveBeenCalledTimes(2);
  });

  it('rejects malformed queue values before Taski or model activity', async () => {
    const fetchImplementation = taskiFetch('created');
    const model = runner();
    await expect(processIncident('{', config, dependencies(fetchImplementation, model))).rejects.toThrow('invalid_message');
    expect(fetchImplementation).not.toHaveBeenCalled();
    expect(model.run).not.toHaveBeenCalled();
  });
});
