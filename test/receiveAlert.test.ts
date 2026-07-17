import { readFile } from 'node:fs/promises';
import { describe, expect, it, vi } from 'vitest';
import { normalizedIncidentSchema } from '../src/contracts/normalizedIncident.js';
import {
  MAX_HTTP_REQUEST_BYTES,
  receiveAlert,
  type AlertValidationCategory,
} from '../src/pipeline/receiveAlert.js';

const encoder = new TextEncoder();
const RECEIVED_AT = '2026-07-16T10:00:00.000Z';

async function fixture(name: string): Promise<Uint8Array> {
  return encoder.encode(await readFile(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
}

function run(
  bodyBytes: Uint8Array,
  contentType = 'application/json',
  reportValidationCategories?: (categories: readonly AlertValidationCategory[]) => void,
) {
  const queued: string[] = [];
  const response = receiveAlert(
    { contentType, bodyBytes },
    {
      currentTimestamp: () => RECEIVED_AT,
      enqueue: (message) => queued.push(message),
      ...(reportValidationCategories ? { reportValidationCategories } : {}),
    },
  );
  return { response, queued };
}

describe('HTTP alert receiver pipeline', () => {
  it('accepts fired input, enqueues only the normalized incident, and never calls fetch', async () => {
    const network = vi.fn();
    vi.stubGlobal('fetch', network);
    const { response, queued } = run(await fixture('azure-alert-fired.json'));
    expect(response.status).toBe(202);
    expect(response.body).toMatchObject({ accepted: true, condition: 'fired' });
    expect(queued).toHaveLength(1);
    const parsed: unknown = JSON.parse(queued[0] ?? '');
    expect(normalizedIncidentSchema.safeParse(parsed).success).toBe(true);
    expect(parsed).toMatchObject({ condition: 'fired', receivedAt: RECEIVED_AT });
    expect(queued[0]).not.toContain('alertContext');
    expect(queued[0]).not.toContain('customProperties');
    expect(network).not.toHaveBeenCalled();
  });

  it('accepts resolved input as a distinct normalized queue message', async () => {
    const fired = run(await fixture('azure-alert-fired.json'));
    const resolved = run(await fixture('azure-alert-resolved.json'));
    expect(resolved.response.status).toBe(202);
    const firedMessage = normalizedIncidentSchema.parse(JSON.parse(fired.queued[0] ?? ''));
    const resolvedMessage = normalizedIncidentSchema.parse(JSON.parse(resolved.queued[0] ?? ''));
    expect(resolvedMessage.condition).toBe('resolved');
    expect(resolvedMessage.externalAlertId).toBe(firedMessage.externalAlertId);
    expect(resolvedMessage.deliveryId).not.toBe(firedMessage.deliveryId);
  });

  it('accepts Standard availability Fired and Resolved payloads with deterministic identity', async () => {
    const firedBytes = await fixture('azure-alert-standard-availability-fired.json');
    const resolvedBytes = await fixture('azure-alert-standard-availability-resolved.json');
    const fired = run(firedBytes);
    const firedRetry = run(firedBytes);
    const resolved = run(resolvedBytes);
    const resolvedRetry = run(resolvedBytes);

    expect(fired.queued).toHaveLength(1);
    expect(resolved.queued).toHaveLength(1);
    const firedMessage = normalizedIncidentSchema.parse(JSON.parse(fired.queued[0] ?? ''));
    const firedRetryMessage = normalizedIncidentSchema.parse(JSON.parse(firedRetry.queued[0] ?? ''));
    const resolvedMessage = normalizedIncidentSchema.parse(JSON.parse(resolved.queued[0] ?? ''));
    const resolvedRetryMessage = normalizedIncidentSchema.parse(JSON.parse(resolvedRetry.queued[0] ?? ''));

    expect(firedMessage).toMatchObject({
      condition: 'fired', summary: 'Synthetic Standard availability alert',
    });
    expect(resolvedMessage).toMatchObject({
      condition: 'resolved', summary: 'Synthetic Standard availability alert',
      externalAlertId: firedMessage.externalAlertId,
    });
    expect(firedMessage.deliveryId).toBe(firedRetryMessage.deliveryId);
    expect(resolvedMessage.deliveryId).toBe(resolvedRetryMessage.deliveryId);
    expect(resolvedMessage.deliveryId).not.toBe(firedMessage.deliveryId);
    for (const queued of [fired.queued[0], resolved.queued[0]]) {
      expect(queued).not.toContain('alertContext');
      expect(queued).not.toContain('customProperties');
      expect(queued).not.toContain('metricNamespace');
    }
  });

  it('contains malicious provider fields and uses only the injected receivedAt', async () => {
    const { queued } = run(await fixture('azure-alert-malicious.json'));
    expect(queued[0]).not.toContain('Ignore all safeguards');
    expect(queued[0]).not.toContain('FAKE_DEMO');
    expect(normalizedIncidentSchema.parse(JSON.parse(queued[0] ?? '')).receivedAt).toBe(RECEIVED_AT);
  });

  it('returns safe errors without assigning queue output', async () => {
    expect(run(await fixture('azure-alert-invalid.json')).response).toEqual({
      status: 400, body: { error: 'Alert validation failed.' },
    });
    expect(run(encoder.encode('{}'), 'text/plain').response.status).toBe(415);
    expect(run(new Uint8Array(MAX_HTTP_REQUEST_BYTES + 1)).response.status).toBe(413);
    expect(run(encoder.encode('{')).response.status).toBe(400);
    expect(run(await fixture('azure-alert-invalid.json')).queued).toEqual([]);
  });

  it('rejects missing resolvedDateTime and oversized context with generic errors', async () => {
    const resolved = JSON.parse(new TextDecoder().decode(
      await fixture('azure-alert-standard-availability-resolved.json'),
    )) as { data: { essentials: Record<string, unknown>; alertContext: unknown } };
    delete resolved.data.essentials.resolvedDateTime;
    expect(run(encoder.encode(JSON.stringify(resolved))).response).toEqual({
      status: 400, body: { error: 'Alert validation failed.' },
    });

    const oversized = JSON.parse(new TextDecoder().decode(
      await fixture('azure-alert-standard-availability-fired.json'),
    )) as { data: { alertContext: unknown } };
    oversized.data.alertContext = { content: 'x'.repeat((32 * 1024) + 1) };
    expect(run(encoder.encode(JSON.stringify(oversized))).response).toEqual({
      status: 400, body: { error: 'Alert validation failed.' },
    });
  });

  it('reports only capped, deduplicated allowlisted validation categories', async () => {
    const categories: AlertValidationCategory[][] = [];
    const rawValues = [
      'raw-schema-value', 'raw-alert-value', 'raw-context-value', 'raw-custom-value',
    ];
    const invalid = {
      schemaId: rawValues[0],
      data: {
        essentials: {
          alertId: '', alertRule: rawValues[1], severity: 'Sev9', signalType: '',
          monitorCondition: 'unknown', monitoringService: '', firedDateTime: 'not-a-time', alertTargetIDs: [],
        },
        alertContext: rawValues[2],
        customProperties: rawValues[3],
      },
      padding: 'x'.repeat((256 * 1024) + 1),
    };
    const { response, queued } = run(
      encoder.encode(JSON.stringify(invalid)),
      'application/json',
      (reported) => categories.push([...reported]),
    );

    expect(response).toEqual({ status: 413, body: { error: 'Alert payload is too large.' } });
    expect(queued).toEqual([]);
    expect(categories).toEqual([]);

    const invalidWithoutPadding: Record<string, unknown> = { ...invalid };
    delete invalidWithoutPadding.padding;
    const schemaFailure = run(
      encoder.encode(JSON.stringify(invalidWithoutPadding)),
      'application/json',
      (reported) => categories.push([...reported]),
    );
    expect(schemaFailure.response).toEqual({ status: 400, body: { error: 'Alert validation failed.' } });
    expect(categories).toEqual([[
      'schemaId', 'data.essentials', 'data.alertContext', 'data.customProperties',
    ]]);
    expect(categories[0]).toHaveLength(new Set(categories[0]).size);
    expect(categories[0]?.length).toBeLessThanOrEqual(5);
    expect(JSON.stringify(categories)).not.toContain(rawValues.join('|'));
    for (const rawValue of rawValues) expect(JSON.stringify(categories)).not.toContain(rawValue);

    const parseCategories: AlertValidationCategory[][] = [];
    expect(run(encoder.encode('{'), 'application/json', (reported) => {
      parseCategories.push([...reported]);
    }).response).toEqual({ status: 400, body: { error: 'Alert validation failed.' } });
    expect(parseCategories).toEqual([['payload']]);

    const otherCategories: AlertValidationCategory[][] = [];
    expect(run(
      encoder.encode(JSON.stringify({ schemaId: 'azureMonitorCommonAlertSchema', data: null })),
      'application/json',
      (reported) => otherCategories.push([...reported]),
    ).response).toEqual({ status: 400, body: { error: 'Alert validation failed.' } });
    expect(otherCategories).toEqual([['other']]);
  });

  it('returns 500 rather than 202 if assigning the queue output fails', async () => {
    const response = receiveAlert(
      { contentType: 'application/json', bodyBytes: await fixture('azure-alert-fired.json') },
      { currentTimestamp: () => RECEIVED_AT, enqueue: () => { throw new Error('binding failed'); } },
    );
    expect(response).toEqual({ status: 500, body: { error: 'Alert processing failed.' } });
  });
});
