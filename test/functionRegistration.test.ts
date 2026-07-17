import { access, readFile } from 'node:fs/promises';
import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.doUnmock('@azure/functions');
});

describe('Azure Functions v4 registration', () => {
  it('loads both registration modules without network access', async () => {
    const network = vi.fn(() => { throw new Error('Network access is forbidden during registration.'); });
    vi.stubGlobal('fetch', network);
    await expect(import('../src/functions/receiveAzureAlert.js')).resolves.toHaveProperty('receiveAzureAlertHandler');
    await expect(import('../src/functions/processIncident.js')).resolves.toHaveProperty('processIncidentHandler');
    expect(network).not.toHaveBeenCalled();
  });

  it('registers the HTTP and queue functions with the production binding contract', async () => {
    vi.resetModules();
    const http = vi.fn();
    const storageQueue = vi.fn();
    const queueOutput = Object.freeze({ kind: 'synthetic-queue-output' });
    const outputStorageQueue = vi.fn(() => queueOutput);
    vi.doMock('@azure/functions', () => ({
      app: { http, storageQueue },
      output: { storageQueue: outputStorageQueue },
    }));

    await import('../src/functions/receiveAzureAlert.js');
    await import('../src/functions/processIncident.js');

    expect(outputStorageQueue).toHaveBeenCalledWith({
      queueName: '%AZURE_INCIDENT_QUEUE_NAME%', connection: 'AzureWebJobsStorage',
    });
    expect(http).toHaveBeenCalledWith('receiveAzureAlert', expect.objectContaining({
      route: 'alerts/azure-monitor', methods: ['POST'], authLevel: 'function', extraOutputs: [queueOutput],
      handler: expect.any(Function),
    }));
    expect(storageQueue).toHaveBeenCalledWith('processIncident', expect.objectContaining({
      queueName: '%AZURE_INCIDENT_QUEUE_NAME%', connection: 'AzureWebJobsStorage',
      handler: expect.any(Function),
    }));
  });

  it('points package main at both compiled registration modules', async () => {
    const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8')) as {
      main?: string;
    };
    expect(packageJson.main).toBe('dist/src/functions/*.js');
    await expect(access(new URL('../dist/src/functions/receiveAzureAlert.js', import.meta.url))).resolves.toBeUndefined();
    await expect(access(new URL('../dist/src/functions/processIncident.js', import.meta.url))).resolves.toBeUndefined();
  });

  it('keeps host.json and package.json at the deployment root', async () => {
    const host = JSON.parse(await readFile(new URL('../host.json', import.meta.url), 'utf8')) as { version?: string };
    const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8')) as {
      engines?: { node?: string };
    };
    expect(host.version).toBe('2.0');
    expect(packageJson.engines?.node).toBe('>=22.0.0');
  });

  it('configures plain UTF-8 queue messages and bounded poison retries', async () => {
    const host = JSON.parse(await readFile(new URL('../host.json', import.meta.url), 'utf8')) as {
      extensions?: { queues?: Record<string, unknown> };
    };
    expect(host.extensions?.queues).toMatchObject({ messageEncoding: 'none', maxDequeueCount: 5 });
  });
});
