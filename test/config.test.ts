import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ConfigurationError,
  validateEnvironment,
  validateOpenAIEnvironment,
  validateTaskiEnvironment,
  validateTriageIdentityEnvironment,
} from '../src/config/env.js';

const fakeEnvironment = {
  NODE_ENV: 'test',
  AzureWebJobsStorage: 'UseDevelopmentStorage=true',
  AZURE_INCIDENT_QUEUE_NAME: 'taski-incident-events',
  TASKI_INTERNAL_BASE_URL: 'https://taski.example.invalid/',
  TASKI_INCIDENT_KEY_ID: 'synthetic-key-id',
  TASKI_INCIDENT_SECRET: '0123456789abcdef0123456789abcdef',
  TASKI_REQUEST_TIMEOUT_MS: '10000',
  OPENAI_API_KEY: 'test-openai-api-key-00000000000000000000',
  OPENAI_MODEL: 'test-model',
  OPENAI_REQUEST_TIMEOUT_MS: '30000',
  OPENAI_MAX_TURNS: '5',
  OPENAI_TRACING_ENABLED: 'false',
  TRIAGE_POLICY_VERSION: 'policy-v1',
};

afterEach(() => vi.unstubAllEnvs());

describe('Batch 5B runtime configuration contract', () => {
  it('accepts explicitly supplied synthetic pipeline configuration', () => {
    const parsed = validateEnvironment(fakeEnvironment, { requirePipelineSettings: true });
    expect(parsed).toMatchObject({
      NODE_ENV: 'test', AZURE_INCIDENT_QUEUE_NAME: 'taski-incident-events',
      TASKI_REQUEST_TIMEOUT_MS: 10_000,
      OPENAI_REQUEST_TIMEOUT_MS: 30_000, OPENAI_MAX_TURNS: 5,
      OPENAI_TRACING_ENABLED: false, OPENAI_MODEL: 'test-model',
    });
  });

  it('keeps ordinary imports and Batch 1 utilities credential-free', () => {
    expect(validateEnvironment({})).toEqual({
      NODE_ENV: 'development', TASKI_REQUEST_TIMEOUT_MS: 10_000,
      OPENAI_REQUEST_TIMEOUT_MS: 30_000, OPENAI_MAX_TURNS: 6,
      OPENAI_TRACING_ENABLED: false,
    });
  });

  it('validates Taski transport independently from malformed or missing AI settings', () => {
    const taski = validateTaskiEnvironment({
      ...fakeEnvironment,
      OPENAI_API_KEY: 'short',
      OPENAI_MODEL: 'bad model',
      OPENAI_MAX_TURNS: '999',
      TRIAGE_POLICY_VERSION: 'bad policy',
    });
    expect(taski).toEqual({
      TASKI_INTERNAL_BASE_URL: 'https://taski.example.invalid/',
      TASKI_INCIDENT_KEY_ID: 'synthetic-key-id',
      TASKI_INCIDENT_SECRET: '0123456789abcdef0123456789abcdef',
      TASKI_REQUEST_TIMEOUT_MS: 10_000,
    });
  });

  it('validates triage identity and OpenAI execution in separate bounded contracts', () => {
    expect(validateTriageIdentityEnvironment(fakeEnvironment)).toEqual({
      TRIAGE_POLICY_VERSION: 'policy-v1',
    });
    expect(validateOpenAIEnvironment(fakeEnvironment)).toMatchObject({
      OPENAI_MODEL: 'test-model', OPENAI_REQUEST_TIMEOUT_MS: 30_000,
      OPENAI_MAX_TURNS: 5, OPENAI_TRACING_ENABLED: false,
    });
    expect(() => validateTriageIdentityEnvironment({})).toThrow('TRIAGE_POLICY_VERSION');
    expect(() => validateOpenAIEnvironment({})).toThrow(/OPENAI_API_KEY.*OPENAI_MODEL/);
  });

  it('reports missing field names only', () => {
    expect(() => validateEnvironment({ NODE_ENV: 'test' }, { requirePipelineSettings: true }))
      .toThrow(/AzureWebJobsStorage.*AZURE_INCIDENT_QUEUE_NAME.*TASKI_INTERNAL_BASE_URL/);
  });

  it('never includes a supplied secret or invalid value in an error', () => {
    const secret = 'visible-value-must-not-appear';
    try {
      validateEnvironment({ ...fakeEnvironment, TASKI_INCIDENT_SECRET: secret }, { requirePipelineSettings: true });
      throw new Error('Expected invalid configuration to fail.');
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigurationError);
      expect(error instanceof Error ? error.message : '').not.toContain(secret);
      expect(error instanceof Error ? error.message : '').toContain('TASKI_INCIDENT_SECRET');
    }
  });

  it('enforces Azure queue names', () => {
    for (const queueName of ['ab', 'Uppercase', 'bad--queue', '-leading', 'trailing-']) {
      expect(() => validateEnvironment({ ...fakeEnvironment, AZURE_INCIDENT_QUEUE_NAME: queueName }))
        .toThrow('AZURE_INCIDENT_QUEUE_NAME');
    }
  });

  it('requires HTTPS except explicit localhost and rejects embedded credentials', () => {
    expect(() => validateEnvironment({ ...fakeEnvironment, TASKI_INTERNAL_BASE_URL: 'http://taski.example.invalid' }))
      .toThrow('TASKI_INTERNAL_BASE_URL');
    expect(validateEnvironment({ ...fakeEnvironment, TASKI_INTERNAL_BASE_URL: 'http://localhost:3000' })
      .TASKI_INTERNAL_BASE_URL).toBe('http://localhost:3000');
    expect(() => validateEnvironment({
      ...fakeEnvironment, TASKI_INTERNAL_BASE_URL: 'https://user:password@taski.example.invalid',
    })).toThrow('TASKI_INTERNAL_BASE_URL');
  });

  it('enforces bounded integer request timeouts', () => {
    for (const timeout of ['999', '30001', '1.5', 'not-a-number']) {
      expect(() => validateEnvironment({ ...fakeEnvironment, TASKI_REQUEST_TIMEOUT_MS: timeout }))
        .toThrow('TASKI_REQUEST_TIMEOUT_MS');
    }
  });

  it('validates bounded AI timeout, turns, model, policy, and explicit tracing opt-in', () => {
    for (const timeout of ['999', '120001', 'not-a-number']) {
      expect(() => validateEnvironment({ ...fakeEnvironment, OPENAI_REQUEST_TIMEOUT_MS: timeout }))
        .toThrow('OPENAI_REQUEST_TIMEOUT_MS');
    }
    for (const turns of ['0', '9', '1.5']) {
      expect(() => validateEnvironment({ ...fakeEnvironment, OPENAI_MAX_TURNS: turns }))
        .toThrow('OPENAI_MAX_TURNS');
    }
    expect(validateEnvironment({ ...fakeEnvironment, OPENAI_TRACING_ENABLED: 'true' }).OPENAI_TRACING_ENABLED)
      .toBe(true);
    expect(() => validateEnvironment({ ...fakeEnvironment, OPENAI_TRACING_ENABLED: 'yes' }))
      .toThrow('OPENAI_TRACING_ENABLED');
    expect(() => validateEnvironment({ ...fakeEnvironment, OPENAI_MODEL: 'bad model' })).toThrow('OPENAI_MODEL');
    expect(() => validateEnvironment({ ...fakeEnvironment, TRIAGE_POLICY_VERSION: 'bad policy' }))
      .toThrow('TRIAGE_POLICY_VERSION');
    expect(() => validateEnvironment({ ...fakeEnvironment, TRIAGE_POLICY_VERSION: `p${'x'.repeat(48)}` }))
      .toThrow('TRIAGE_POLICY_VERSION');
  });

  it('never exposes an API key in validation errors', () => {
    const apiKey = 'short-secret-value';
    try {
      validateEnvironment({ ...fakeEnvironment, OPENAI_API_KEY: apiKey }, { requirePipelineSettings: true });
      throw new Error('Expected invalid configuration to fail.');
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigurationError);
      expect(error instanceof Error ? error.message : '').toBe('Invalid configuration fields: OPENAI_API_KEY.');
      expect(error instanceof Error ? error.message : '').not.toContain(apiKey);
    }
  });

  it('ignores unrelated environment variables and does not parse process.env at import', async () => {
    expect(validateEnvironment({ NODE_ENV: 'test', UNRELATED_SETTING: 'ignored' })).toEqual({
      NODE_ENV: 'test', TASKI_REQUEST_TIMEOUT_MS: 10_000,
      OPENAI_REQUEST_TIMEOUT_MS: 30_000, OPENAI_MAX_TURNS: 6,
      OPENAI_TRACING_ENABLED: false,
    });
    vi.stubEnv('NODE_ENV', 'unsupported-import-value');
    vi.resetModules();
    await expect(import('../src/config/env.js')).resolves.toHaveProperty('validateEnvironment');
  });
});
