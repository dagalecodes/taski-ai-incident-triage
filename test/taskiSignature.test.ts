import { describe, expect, it } from 'vitest';
import { normalizedIncidentSchema } from '../src/contracts/normalizedIncident.js';
import { signTaskiIncident } from '../src/security/taskiSignature.js';

const incident = normalizedIncidentSchema.parse({
  schemaVersion: 1,
  provider: 'azure_monitor',
  externalAlertId: 'synthetic-alert',
  deliveryId: `sha256:${'a'.repeat(64)}`,
  condition: 'fired',
  severity: 'warning',
  alertRule: 'Synthetic rule',
  affectedService: 'synthetic-service',
  targetResourceId: '/subscriptions/000/resourceGroups/demo/providers/Microsoft.Web/sites/synthetic',
  signalType: 'Metric',
  monitoringService: 'Platform',
  summary: 'Synthetic summary.',
  occurredAt: '2026-07-15T08:00:00.000Z',
  receivedAt: '2026-07-16T10:00:00.000Z',
});

const config = { keyId: 'synthetic-key', secret: '0123456789abcdef0123456789abcdef' };

describe('Taski exact-body signature', () => {
  it('is deterministic lowercase HMAC-SHA256 and retains the exact body bytes', () => {
    const first = signTaskiIncident(incident, 1_752_659_200, config);
    const second = signTaskiIncident(incident, 1_752_659_200, config);
    expect(first.headers['X-Taski-Signature']).toBe(second.headers['X-Taski-Signature']);
    expect(first.headers['X-Taski-Signature']).toMatch(/^[a-f0-9]{64}$/);
    expect(first.headers['X-Taski-Timestamp']).toBe('1752659200');
    expect(JSON.parse(first.bodyBytes.toString('utf8'))).toEqual(incident);
  });

  it('changes for a one-byte body change and timestamp change', () => {
    const original = signTaskiIncident(incident, 1_752_659_200, config);
    const changedBody = signTaskiIncident({ ...incident, summary: 'Synthetic summary!' }, 1_752_659_200, config);
    const changedTime = signTaskiIncident(incident, 1_752_659_201, config);
    expect(changedBody.headers['X-Taski-Signature']).not.toBe(original.headers['X-Taski-Signature']);
    expect(changedTime.headers['X-Taski-Signature']).not.toBe(original.headers['X-Taski-Signature']);
  });

  it('rejects unsafe secrets, key IDs, and timestamps without exposing values', () => {
    expect(() => signTaskiIncident(incident, 1, { ...config, secret: 'short' })).toThrow('configuration');
    expect(() => signTaskiIncident(incident, 1, { ...config, secret: 'x'.repeat(4_097) })).toThrow('configuration');
    expect(() => signTaskiIncident(incident, 0, config)).toThrow('configuration');
    expect(() => signTaskiIncident(incident, 1, { ...config, keyId: '' })).toThrow('configuration');
  });
});
