import { afterEach, describe, expect, it, vi } from 'vitest';
import { normalizedIncidentSchema } from '../src/contracts/normalizedIncident.js';
import { sendTaskiIncident } from '../src/integrations/taskiClient.js';
import { signTaskiIncident } from '../src/security/taskiSignature.js';

const incident = normalizedIncidentSchema.parse({
  schemaVersion: 1, provider: 'azure_monitor', externalAlertId: 'synthetic-alert',
  deliveryId: `sha256:${'b'.repeat(64)}`, condition: 'fired', severity: 'warning',
  alertRule: 'Synthetic rule', affectedService: 'synthetic-service',
  targetResourceId: '/subscriptions/000/resourceGroups/demo/providers/Microsoft.Web/sites/synthetic',
  signalType: 'Metric', monitoringService: 'Platform', summary: 'Synthetic summary.',
  occurredAt: '2026-07-15T08:00:00.000Z', receivedAt: '2026-07-16T10:00:00.000Z',
});
const signed = signTaskiIncident(incident, 1_752_659_200, {
  keyId: 'synthetic-key', secret: '0123456789abcdef0123456789abcdef',
});
const success = (status: 'created' | 'updated' | 'duplicate' | 'stale') => ({
  status, incidentId: 7, messageId: 12, alertState: 'fired',
  analysisId: null, analysisStatus: 'pending' as const, version: 1,
});

afterEach(() => {
  vi.useRealTimers();
});

describe('Taski HTTP client', () => {
  it.each(['created', 'updated', 'duplicate', 'stale'] as const)('accepts safe %s responses', async (status) => {
    const fetchImplementation = vi.fn(async (_input: Parameters<typeof fetch>[0], _init?: Parameters<typeof fetch>[1]) => new Response(JSON.stringify(success(status)), {
      status: 200, headers: { 'content-type': 'application/json' },
    })) as unknown as typeof fetch;
    await expect(sendTaskiIncident(signed, {
      baseUrl: 'https://taski.example.invalid/', timeoutMs: 10_000, fetchImplementation,
    })).resolves.toEqual(success(status));
  });

  it('uses the exact endpoint, headers, signed bytes, timeout signal, and manual redirects', async () => {
    const fetchImplementation = vi.fn(async (_input: Parameters<typeof fetch>[0], _init?: Parameters<typeof fetch>[1]) => new Response(JSON.stringify(success('created')), { status: 201 }));
    await sendTaskiIncident(signed, {
      baseUrl: 'https://taski.example.invalid///', timeoutMs: 10_000,
      fetchImplementation: fetchImplementation as unknown as typeof fetch,
    });
    expect(fetchImplementation).toHaveBeenCalledOnce();
    const [url, init] = fetchImplementation.mock.calls[0] ?? [];
    expect(url).toBe('https://taski.example.invalid/api/incidents/integrations/azure-monitor');
    expect(init).toMatchObject({ method: 'POST', redirect: 'manual' });
    expect(init?.headers).toEqual(signed.headers);
    expect(Buffer.from(init?.body as Uint8Array)).toEqual(signed.bodyBytes);
    expect(init?.signal).toBeInstanceOf(AbortSignal);
  });

  it.each([401, 429, 500])('fails safely for HTTP %i without exposing the response body', async (status) => {
    const marker = `sensitive-response-${status}`;
    const fetchImplementation = vi.fn(async () => new Response(marker, { status }));
    await expect(sendTaskiIncident(signed, {
      baseUrl: 'https://taski.example.invalid', timeoutMs: 10_000,
      fetchImplementation: fetchImplementation as unknown as typeof fetch,
    })).rejects.toSatisfy((error: Error) => !error.message.includes(marker));
  });

  it('rejects invalid JSON, unknown status, unknown fields, and network failure safely', async () => {
    for (const body of ['not-json', JSON.stringify({ ...success('created'), status: 'ignored' }),
      JSON.stringify({ ...success('created'), extra: 'untrusted' })]) {
      const fetchImplementation = vi.fn(async () => new Response(body, { status: 200 }));
      await expect(sendTaskiIncident(signed, {
        baseUrl: 'https://taski.example.invalid', timeoutMs: 10_000,
        fetchImplementation: fetchImplementation as unknown as typeof fetch,
      })).rejects.toThrow('remote');
    }
    const failedFetch = vi.fn(async () => { throw new Error('private network details'); });
    await expect(sendTaskiIncident(signed, {
      baseUrl: 'https://taski.example.invalid', timeoutMs: 10_000,
      fetchImplementation: failedFetch as unknown as typeof fetch,
    })).rejects.toThrow('network');
  });

  it('requires bounded safe analysis identity fields', async () => {
    const invalidBodies = [
      { ...success('created'), analysisId: undefined },
      { ...success('created'), analysisStatus: undefined },
      { ...success('created'), analysisId: '' },
      { ...success('created'), analysisId: 'bad identity' },
      { ...success('created'), analysisId: `analysis:${'x'.repeat(121)}` },
      { ...success('created'), analysisStatus: 'completed' },
    ];
    for (const body of invalidBodies) {
      const fetchImplementation = vi.fn(async () => new Response(JSON.stringify(body), { status: 200 }));
      await expect(sendTaskiIncident(signed, {
        baseUrl: 'https://taski.example.invalid', timeoutMs: 10_000,
        fetchImplementation: fetchImplementation as unknown as typeof fetch,
      })).rejects.toThrow('remote');
    }
  });

  it('rejects insecure remote URLs and embedded credentials before fetch', async () => {
    const fetchImplementation = vi.fn();
    for (const baseUrl of ['http://taski.example.invalid',
      'https://user:password@taski.example.invalid']) {
      await expect(sendTaskiIncident(signed, {
        baseUrl, timeoutMs: 10_000,
        fetchImplementation: fetchImplementation as unknown as typeof fetch,
      })).rejects.toThrow('configuration');
    }
    expect(fetchImplementation).not.toHaveBeenCalled();
  });

  it('aborts a request at the configured timeout', async () => {
    vi.useFakeTimers();
    const fetchImplementation = vi.fn((_url: URL | RequestInfo, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
    }));
    const rejection = expect(sendTaskiIncident(signed, {
      baseUrl: 'https://taski.example.invalid', timeoutMs: 1_000,
      fetchImplementation: fetchImplementation as unknown as typeof fetch,
    })).rejects.toThrow('timeout');
    await vi.advanceTimersByTimeAsync(1_000);
    await rejection;
    expect((fetchImplementation.mock.calls[0]?.[1] as RequestInit | undefined)?.signal?.aborted).toBe(true);
  });
});
