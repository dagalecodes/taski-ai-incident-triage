import { createHmac } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { normalizedIncidentSchema } from '../src/contracts/normalizedIncident.js';
import { processIncident } from '../src/pipeline/processIncident.js';

const incident = normalizedIncidentSchema.parse({
  schemaVersion: 1, provider: 'azure_monitor', externalAlertId: 'synthetic-alert',
  deliveryId: `sha256:${'c'.repeat(64)}`, condition: 'resolved', severity: 'informational',
  alertRule: 'Synthetic rule', affectedService: 'synthetic-service',
  targetResourceId: '/subscriptions/000/resourceGroups/demo/providers/Microsoft.Web/sites/synthetic',
  signalType: 'Metric', monitoringService: 'Platform', summary: 'Synthetic recovery.',
  occurredAt: '2026-07-15T08:06:30.000Z', receivedAt: '2026-07-16T10:00:00.000Z',
});
const secret = '0123456789abcdef0123456789abcdef';
const config = {
  taskiBaseUrl: 'https://taski.example.invalid', keyId: 'synthetic-key', secret, timeoutMs: 10_000,
};

describe('normalized incident queue processor', () => {
  it.each(['created', 'updated', 'duplicate', 'stale'] as const)('forwards and completes for %s', async (status) => {
    const fetchImplementation = vi.fn(async (_input: Parameters<typeof fetch>[0], _init?: Parameters<typeof fetch>[1]) => new Response(JSON.stringify({
      status, incidentId: 7, messageId: 12, alertState: 'resolved', version: 2,
    }), { status: 200 }));
    const processed = await processIncident(JSON.stringify(incident), config, {
      fetchImplementation: fetchImplementation as unknown as typeof fetch,
      currentEpochSeconds: () => 1_752_659_200,
    });
    expect(processed.result.status).toBe(status);
  });

  it('sends the same exact bytes used by the HMAC', async () => {
    const fetchImplementation = vi.fn(async (_input: Parameters<typeof fetch>[0], _init?: Parameters<typeof fetch>[1]) => new Response(JSON.stringify({
      status: 'created', incidentId: 7, messageId: 12, alertState: 'resolved', version: 2,
    }), { status: 201 }));
    await processIncident(incident, config, {
      fetchImplementation: fetchImplementation as unknown as typeof fetch,
      currentEpochSeconds: () => 1_752_659_200,
    });
    const init = fetchImplementation.mock.calls[0]?.[1];
    const sentBytes = Buffer.from(init?.body as Uint8Array);
    const expected = createHmac('sha256', Buffer.from(secret, 'utf8'))
      .update(Buffer.from('1752659200.', 'utf8')).update(sentBytes).digest('hex');
    expect((init?.headers as Record<string, string>)['X-Taski-Signature']).toBe(expected);
    expect(JSON.parse(sentBytes.toString('utf8'))).toEqual(incident);
  });

  it('rejects malformed, unknown-field, and unsupported-version messages before fetch', async () => {
    const fetchImplementation = vi.fn();
    for (const message of ['{', JSON.stringify({ ...incident, extra: true }),
      JSON.stringify({ ...incident, schemaVersion: 2 })]) {
      await expect(processIncident(message, config, {
        fetchImplementation: fetchImplementation as unknown as typeof fetch,
        currentEpochSeconds: () => 1_752_659_200,
      })).rejects.toThrow('invalid_message');
    }
    expect(fetchImplementation).not.toHaveBeenCalled();
  });
});
