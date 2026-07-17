import { afterEach, describe, expect, it, vi } from 'vitest';
import { taskiTriageResultSchema } from '../src/contracts/taskiTriageResult.js';
import { sendTaskiTriageResult } from '../src/integrations/taskiClient.js';
import { signTaskiBody } from '../src/security/taskiSignature.js';

const payload = taskiTriageResultSchema.parse({
  schemaVersion: 1, incidentId: 7, provider: 'azure_monitor', externalAlertId: 'synthetic-alert',
  sourceDeliveryId: `sha256:${'f'.repeat(64)}`, analysisStatus: 'completed',
  analysisId: `analysis:policy-v1:${'a'.repeat(64)}`,
  diagnosis: {
    schemaVersion: 1, classification: 'unknown', probableCause: 'Insufficient fixture evidence.',
    confidence: 0.2, evidence: [],
    recommendedActions: [{ action: 'Review the incident manually.', requiresHumanApproval: true }],
    limitations: ['Diagnostic providers were unavailable.'],
  },
  failure: null, completedAt: '2026-07-16T10:01:00.000Z',
});
const signed = signTaskiBody(payload, 1_752_659_200, {
  keyId: 'synthetic-key', secret: '0123456789abcdef0123456789abcdef',
});
const options = { baseUrl: 'https://taski.example.invalid', timeoutMs: 10_000 };

afterEach(() => vi.useRealTimers());

describe('Taski triage-result client', () => {
  it.each(['updated', 'duplicate', 'stale'] as const)('accepts strict %s responses', async status => {
    const fetchImplementation = vi.fn(async (_input: Parameters<typeof fetch>[0], _init?: Parameters<typeof fetch>[1]) => new Response(JSON.stringify({
      status, incidentId: 7, messageId: 12, alertState: 'fired', analysisStatus: 'ready', version: 3,
    }), { status: 200 }));
    await expect(sendTaskiTriageResult(signed, {
      ...options, fetchImplementation: fetchImplementation as unknown as typeof fetch,
    })).resolves.toMatchObject({ status, incidentId: 7 });
  });

  it('uses the dedicated endpoint and transmits the exact signed bytes', async () => {
    const fetchImplementation = vi.fn(async (_input: Parameters<typeof fetch>[0], _init?: Parameters<typeof fetch>[1]) => new Response(JSON.stringify({
      status: 'updated', incidentId: 7, messageId: 12, alertState: 'fired', analysisStatus: 'ready', version: 3,
    }), { status: 200 }));
    await sendTaskiTriageResult(signed, {
      ...options, fetchImplementation: fetchImplementation as unknown as typeof fetch,
    });
    const [url, init] = fetchImplementation.mock.calls[0] ?? [];
    expect(url).toBe('https://taski.example.invalid/api/incidents/integrations/triage-results');
    expect(init).toMatchObject({ method: 'POST', redirect: 'manual' });
    expect(Buffer.from(init?.body as Uint8Array)).toEqual(signed.bodyBytes);
  });

  it('rejects invalid status, extra fields, response failures, and timeouts safely', async () => {
    for (const response of [
      { status: 'created', incidentId: 7, messageId: 12, alertState: 'fired', analysisStatus: 'ready', version: 3 },
      { status: 'updated', incidentId: 7, messageId: 12, alertState: 'fired', analysisStatus: 'ready', version: 3, extra: true },
    ]) {
      const fetchImplementation = vi.fn(async () => new Response(JSON.stringify(response), { status: 200 }));
      await expect(sendTaskiTriageResult(signed, {
        ...options, fetchImplementation: fetchImplementation as unknown as typeof fetch,
      })).rejects.toThrow('remote');
    }

    const marker = 'private-response-body';
    const failed = vi.fn(async () => new Response(marker, { status: 500 }));
    await expect(sendTaskiTriageResult(signed, {
      ...options, fetchImplementation: failed as unknown as typeof fetch,
    })).rejects.toSatisfy((error: Error) => !error.message.includes(marker));

    vi.useFakeTimers();
    const hanging = vi.fn((_url: URL | RequestInfo, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
    }));
    const rejection = expect(sendTaskiTriageResult(signed, {
      ...options, timeoutMs: 1_000, fetchImplementation: hanging as unknown as typeof fetch,
    })).rejects.toThrow('timeout');
    await vi.advanceTimersByTimeAsync(1_000);
    await rejection;
  });
});
