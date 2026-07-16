import { readFile } from 'node:fs/promises';
import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('Azure Functions v4 registration', () => {
  it('loads both registration modules without network access', async () => {
    const network = vi.fn(() => { throw new Error('Network access is forbidden during registration.'); });
    vi.stubGlobal('fetch', network);
    await expect(import('../src/functions/receiveAzureAlert.js')).resolves.toHaveProperty('receiveAzureAlertHandler');
    await expect(import('../src/functions/processIncident.js')).resolves.toHaveProperty('processIncidentHandler');
    expect(network).not.toHaveBeenCalled();
  });

  it('points package main at both compiled registration modules', async () => {
    const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8')) as {
      main?: string;
    };
    expect(packageJson.main).toBe('dist/src/functions/*.js');
  });

  it('configures plain UTF-8 queue messages and bounded poison retries', async () => {
    const host = JSON.parse(await readFile(new URL('../host.json', import.meta.url), 'utf8')) as {
      extensions?: { queues?: Record<string, unknown> };
    };
    expect(host.extensions?.queues).toMatchObject({ messageEncoding: 'none', maxDequeueCount: 5 });
  });
});
