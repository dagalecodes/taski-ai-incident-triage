import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { normalizeAzureAlert } from '../src/alerts/normalizeAzureAlert.js';
import { azureMonitorCommonAlertSchema } from '../src/contracts/azureMonitor.js';
import { normalizedIncidentSchema } from '../src/contracts/normalizedIncident.js';
import { canonicalJson } from '../src/shared/canonicalJson.js';

const RECEIVED_AT = '2026-07-16T10:00:00Z';

async function alertFixture(name: string) {
  const raw: unknown = JSON.parse(await readFile(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
  return azureMonitorCommonAlertSchema.parse(raw);
}

describe('normalizeAzureAlert', () => {
  it('maps fired and resolved alerts and validates the output', async () => {
    const fired = normalizeAzureAlert(await alertFixture('azure-alert-fired.json'), RECEIVED_AT);
    const resolved = normalizeAzureAlert(await alertFixture('azure-alert-resolved.json'), RECEIVED_AT);
    expect(fired).toMatchObject({ condition: 'fired', severity: 'error', affectedService: 'taski-demo-api' });
    expect(resolved).toMatchObject({ condition: 'resolved', occurredAt: '2026-07-15T08:06:30.000Z' });
    expect(fired.deliveryId).not.toBe(resolved.deliveryId);
    expect(normalizedIncidentSchema.safeParse(fired).success).toBe(true);
  });

  it('produces the same delivery ID for reordered duplicate properties', async () => {
    const fired = normalizeAzureAlert(await alertFixture('azure-alert-fired.json'), RECEIVED_AT);
    const duplicate = normalizeAzureAlert(await alertFixture('azure-alert-duplicate.json'), RECEIVED_AT);
    expect(duplicate.deliveryId).toBe(fired.deliveryId);
  });

  it('does not include receivedAt in delivery identity', async () => {
    const alert = await alertFixture('azure-alert-fired.json');
    const first = normalizeAzureAlert(alert, RECEIVED_AT);
    const later = normalizeAzureAlert(alert, '2026-07-16T11:00:00Z');
    expect(later.deliveryId).toBe(first.deliveryId);
    expect(later.receivedAt).not.toBe(first.receivedAt);
  });

  it.each([
    ['Sev0', 'critical'], ['Sev1', 'error'], ['Sev2', 'warning'],
    ['Sev3', 'informational'], ['Sev4', 'verbose'],
  ] as const)('maps %s exactly to %s', async (providerSeverity, expected) => {
    const alert = structuredClone(await alertFixture('azure-alert-fired.json'));
    alert.data.essentials.severity = providerSeverity;
    expect(normalizeAzureAlert(alert, RECEIVED_AT).severity).toBe(expected);
  });

  it('does not propagate alertContext, customProperties, injection text, or fake secrets', async () => {
    const normalized = normalizeAzureAlert(await alertFixture('azure-alert-malicious.json'), RECEIVED_AT);
    const serialized = JSON.stringify(normalized);
    expect(serialized).not.toContain('alertContext');
    expect(serialized).not.toContain('customProperties');
    expect(serialized).not.toContain('Ignore all safeguards');
    expect(serialized).not.toContain('FAKE_DEMO');
  });

  it('does not mutate its input', async () => {
    const alert = await alertFixture('azure-alert-fired.json');
    const before = canonicalJson(alert);
    normalizeAzureAlert(alert, RECEIVED_AT);
    expect(canonicalJson(alert)).toBe(before);
  });

  it('canonicalizes object keys without changing the input and rejects unsupported values', () => {
    const input = { z: 1, a: { d: 2, b: [3, 4] } };
    expect(canonicalJson(input)).toBe('{"a":{"b":[3,4],"d":2},"z":1}');
    expect(Object.keys(input)).toEqual(['z', 'a']);
    expect(() => canonicalJson({ invalid: undefined })).toThrow(TypeError);
  });
});
