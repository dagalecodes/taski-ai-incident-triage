import { readFile } from 'node:fs/promises';
import { describe, expect, it, vi } from 'vitest';
import { normalizedIncidentSchema } from '../src/contracts/normalizedIncident.js';
import { MAX_HTTP_REQUEST_BYTES, receiveAlert } from '../src/pipeline/receiveAlert.js';

const encoder = new TextEncoder();
const RECEIVED_AT = '2026-07-16T10:00:00.000Z';

async function fixture(name: string): Promise<Uint8Array> {
  return encoder.encode(await readFile(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
}

function run(bodyBytes: Uint8Array, contentType = 'application/json') {
  const queued: string[] = [];
  const response = receiveAlert(
    { contentType, bodyBytes },
    { currentTimestamp: () => RECEIVED_AT, enqueue: (message) => queued.push(message) },
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

  it('returns 500 rather than 202 if assigning the queue output fails', async () => {
    const response = receiveAlert(
      { contentType: 'application/json', bodyBytes: await fixture('azure-alert-fired.json') },
      { currentTimestamp: () => RECEIVED_AT, enqueue: () => { throw new Error('binding failed'); } },
    );
    expect(response).toEqual({ status: 500, body: { error: 'Alert processing failed.' } });
  });
});
