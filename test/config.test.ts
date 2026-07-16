import { afterEach, describe, expect, it, vi } from 'vitest';
import { ConfigurationError, validateEnvironment } from '../src/config/env.js';

const fakeEnvironment = {
  NODE_ENV: 'test',
  TASKI_INTERNAL_BASE_URL: 'https://taski.example.invalid',
  TASKI_INTEGRATION_KEY_ID: 'fake-key-id',
  TASKI_INTEGRATION_SECRET: 'synthetic-super-secret-value',
  AZURE_STORAGE_CONNECTION_STRING: 'UseDevelopmentStorage=true',
  AZURE_INCIDENT_QUEUE_NAME: 'taski-incident-demo',
  OPENAI_API_KEY: 'fake-openai-key',
};

afterEach(() => vi.unstubAllEnvs());

describe('runtime configuration contract', () => {
  it('accepts explicitly supplied fake strict configuration', () => {
    expect(validateEnvironment(fakeEnvironment, { requireFutureSettings: true }).NODE_ENV).toBe('test');
  });

  it('does not require future settings for Batch 1 build and tests', () => {
    expect(validateEnvironment({})).toEqual({ NODE_ENV: 'development' });
  });

  it('fails explicit strict validation when future settings are missing', () => {
    expect(() => validateEnvironment({ NODE_ENV: 'test' }, { requireFutureSettings: true })).toThrow(ConfigurationError);
  });

  it('never includes a supplied secret value in an error', () => {
    const secret = 'synthetic-super-secret-value';
    try {
      validateEnvironment({ NODE_ENV: secret });
      throw new Error('Expected invalid configuration to fail.');
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigurationError);
      expect(error instanceof Error ? error.message : '').not.toContain(secret);
    }
  });

  it('ignores unrelated environment variables and returns only recognized settings', () => {
    expect(validateEnvironment({ NODE_ENV: 'test', UNRELATED_SETTING: 'ignored' })).toEqual({ NODE_ENV: 'test' });
  });

  it('does not parse process.env at module import', async () => {
    vi.stubEnv('NODE_ENV', 'unsupported-import-value');
    vi.resetModules();
    await expect(import('../src/config/env.js')).resolves.toHaveProperty('validateEnvironment');
  });
});
