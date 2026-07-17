import { readFile } from 'node:fs/promises';
import { describe, expect, it, vi } from 'vitest';
import {
  deterministicFallbackTriage,
  parseDemoArguments,
  runTriageDemo,
  validateStagingTaskiUrl,
  type TriageDemoDependencies,
} from '../scripts/runTriageDemo.js';

const forbiddenNetwork = vi.fn(async () => {
  throw new Error('Real network access is forbidden in tests.');
});

function dependencies(
  output: string[],
  errors: string[],
  environment: Record<string, string> = {},
  overrides: Partial<TriageDemoDependencies> = {},
) {
  const result: TriageDemoDependencies = {
    async readTextFile(path) {
      const fixture = path.includes('resolved') ? 'azure-alert-resolved.json' : 'azure-alert-fired.json';
      return readFile(new URL(`./fixtures/${fixture}`, import.meta.url), 'utf8');
    },
    environment,
    fetchImplementation: forbiddenNetwork as unknown as typeof fetch,
    currentTimestamp: () => '2026-07-16T10:00:00.000Z',
    currentEpochSeconds: () => 1_752_659_200,
    currentIsoTimestamp: () => '2026-07-16T10:01:00.000Z',
    writeOutput: value => output.push(value),
    writeError: value => errors.push(value),
    ...overrides,
  };
  return result;
}

const stagingEnvironment = {
  TASKI_INTERNAL_BASE_URL: 'https://taski-staging.azurewebsites.net',
  TASKI_INCIDENT_KEY_ID: 'synthetic-key-id',
  TASKI_INCIDENT_SECRET: '0123456789abcdef0123456789abcdef',
  TRIAGE_POLICY_VERSION: 'policy-v1',
};

async function dryRun(arguments_: string[] = []) {
  const output: string[] = [];
  const errors: string[] = [];
  forbiddenNetwork.mockClear();
  const code = await runTriageDemo(arguments_, dependencies(output, errors));
  return { code, output, errors, summary: output[0] ? JSON.parse(output[0]) as Record<string, unknown> : null };
}

describe('controlled Batch 5C triage demo', () => {
  it('defaults to a network-free fired-created dry run with safe summary only', async () => {
    const result = await dryRun();
    expect(result.code).toBe(0);
    expect(result.errors).toEqual([]);
    expect(result.summary).toMatchObject({
      mode: 'dry-run', scenario: 'created', condition: 'fired', incidentStatus: 'created',
      incidentId: 7001, triage: 'ran', triageDeliveryStatus: 'updated', analysisStatus: 'completed',
    });
    expect(result.summary).toHaveProperty('analysisId');
    expect(result.output.join('')).not.toMatch(/probableCause|recommendedActions|X-Taski|signature|secret/i);
    expect(forbiddenNetwork).not.toHaveBeenCalled();
  });

  it('rejects unknown flags, secret options, and conflicting confirmations before networking', async () => {
    for (const arguments_ of [
      ['--unknown'],
      ['--taski-secret', 'do-not-accept'],
      ['--openai-api-key', 'do-not-accept'],
      ['--confirm-staging-delivery'],
      ['--confirm-openai-charge'],
      ['--deliver-staging', '--confirm-staging-delivery', '--scenario', 'created'],
    ]) {
      const result = await dryRun(arguments_);
      expect(result.code).toBe(1);
      expect(result.output).toEqual([]);
      expect(result.errors).toEqual(['Triage demo failed safely.\n']);
      expect(forbiddenNetwork).not.toHaveBeenCalled();
    }
  });

  it('requires delivery confirmation and separate OpenAI charge confirmation', async () => {
    expect(parseDemoArguments([]).mode).toBe('dry-run');
    expect(() => parseDemoArguments(['--deliver-staging'])).toThrow();
    expect(() => parseDemoArguments([
      '--deliver-staging', '--confirm-staging-delivery', '--use-openai',
    ])).toThrow();
    expect(parseDemoArguments([
      '--deliver-staging', '--confirm-staging-delivery', '--use-openai', '--confirm-openai-charge',
    ]).mode).toBe('openai-staging');
  });

  it('allows only the exact staging host or bounded localhost and rejects production/arbitrary URLs', () => {
    expect(validateStagingTaskiUrl('https://taski-staging.azurewebsites.net')).toBe(
      'https://taski-staging.azurewebsites.net',
    );
    expect(validateStagingTaskiUrl('http://localhost:3000/')).toBe('http://localhost:3000');
    for (const unsafe of [
      'https://app.taskichat.com',
      'https://taski.example.com',
      'https://taski-staging.azurewebsites.net.evil.example',
      'https://user:password@taski-staging.azurewebsites.net',
      'https://taski-staging.azurewebsites.net/path',
      'https://taski-staging.azurewebsites.net?secret=value',
      'https://taski-staging.azurewebsites.net#fragment',
      'http://localhost:8080',
      'http://127.0.0.1:3000',
    ]) expect(() => validateStagingTaskiUrl(unsafe)).toThrow();
  });

  it('rejects unsafe staging environment without leaking keys, secrets, or raw errors', async () => {
    const output: string[] = [];
    const errors: string[] = [];
    const environment = {
      TASKI_INTERNAL_BASE_URL: 'https://app.taskichat.com',
      TASKI_INCIDENT_KEY_ID: 'private-key-id',
      TASKI_INCIDENT_SECRET: 'private-secret-0123456789abcdefghi',
      TRIAGE_POLICY_VERSION: 'policy-v1',
      OPENAI_API_KEY: 'sk-private-openai-key-1234567890',
      OPENAI_MODEL: 'private-model',
    };
    forbiddenNetwork.mockClear();
    const code = await runTriageDemo(
      ['--deliver-staging', '--confirm-staging-delivery'],
      dependencies(output, errors, environment),
    );
    expect(code).toBe(1);
    expect(output).toEqual([]);
    expect(errors).toEqual(['Triage demo failed safely.\n']);
    expect(errors.join('')).not.toMatch(/private|sk-|app\.taskichat/);
    expect(forbiddenNetwork).not.toHaveBeenCalled();
  });

  it('passes the deterministic honest low-confidence fallback through the real guardrail', () => {
    const diagnosis = deterministicFallbackTriage();
    expect(diagnosis).toMatchObject({ classification: 'unknown', confidence: 0.35, evidence: [] });
    expect(diagnosis.probableCause).toMatch(/only on the alert fixture/i);
    expect(diagnosis.limitations.join(' ')).toMatch(/Live telemetry and OpenAI analysis were not used/i);
    expect(diagnosis.recommendedActions.every(action => action.requiresHumanApproval)).toBe(true);
  });

  it('skips duplicate matching terminal analysis without model or result delivery', async () => {
    const result = await dryRun(['--scenario', 'duplicate-terminal']);
    expect(result.code).toBe(0);
    expect(result.summary).toMatchObject({
      scenario: 'duplicate-terminal', incidentStatus: 'duplicate', triage: 'skipped',
      triageDeliveryStatus: null, analysisStatus: 'ready',
    });
    expect(forbiddenNetwork).not.toHaveBeenCalled();
  });

  it('ingests resolved and stale scenarios while skipping triage', async () => {
    const resolved = await dryRun(['--scenario', 'resolved']);
    expect(resolved.summary).toMatchObject({
      condition: 'resolved', incidentStatus: 'updated', triage: 'skipped', analysisStatus: 'not_required',
    });
    const stale = await dryRun(['--scenario', 'stale']);
    expect(stale.summary).toMatchObject({
      condition: 'fired', incidentStatus: 'stale', triage: 'skipped', analysisStatus: 'pending',
    });
    expect(forbiddenNetwork).not.toHaveBeenCalled();
  });

  it('delivers a safe failed result for the deterministic model-failure scenario', async () => {
    const result = await dryRun(['--scenario', 'model-failure']);
    expect(result.code).toBe(0);
    expect(result.summary).toMatchObject({
      triage: 'ran', triageDeliveryStatus: 'updated', analysisStatus: 'failed',
    });
    expect(result.output.join('')).not.toMatch(/diagnosis|"failure"\s*:|model_unavailable/);
    expect(forbiddenNetwork).not.toHaveBeenCalled();
  });

  it('returns one safe error and nonzero for simulated Taski result-delivery failure', async () => {
    const result = await dryRun(['--scenario', 'result-delivery-failure']);
    expect(result.code).toBe(1);
    expect(result.output).toEqual([]);
    expect(result.errors).toEqual(['Triage demo failed safely.\n']);
    expect(result.errors.join('')).not.toContain('simulated private failure');
    expect(forbiddenNetwork).not.toHaveBeenCalled();
  });

  it('diagnostic flag alone remains a network-free dry run with fixed safe output', async () => {
    const result = await dryRun(['--diagnose-safe-stage']);
    expect(result.code).toBe(0);
    expect(result.summary).toEqual({ stage: 'safe_output', httpStatus: 200 });
    expect(forbiddenNetwork).not.toHaveBeenCalled();
  });

  it('diagnostic flag does not bypass staging confirmation', async () => {
    const result = await dryRun(['--diagnose-safe-stage', '--deliver-staging']);
    expect(result.code).toBe(1);
    expect(result.output).toEqual([]);
    expect(JSON.parse(result.errors.join(''))).toEqual({ stage: 'argument_parsing' });
    expect(forbiddenNetwork).not.toHaveBeenCalled();
  });

  it('reports only incident-ingestion stage, HTTP 400, and safe category', async () => {
    const output: string[] = [];
    const errors: string[] = [];
    const responseBody = 'raw-secret simulated-error https://private.example.invalid';
    const fetchImplementation = vi.fn(async () => new Response(responseBody, { status: 400 }));
    const code = await runTriageDemo([
      '--diagnose-safe-stage', '--deliver-staging', '--confirm-staging-delivery',
    ], dependencies(output, errors, stagingEnvironment, {
      fetchImplementation: fetchImplementation as unknown as typeof fetch,
    }));
    expect(code).toBe(1);
    expect(output).toEqual([]);
    expect(JSON.parse(errors.join(''))).toEqual({
      stage: 'incident_ingestion', httpStatus: 400, category: 'remote',
    });
    expect(errors.join('')).not.toMatch(/raw-secret|simulated-error|private\.example|taski-staging|synthetic-key/);
    expect(fetchImplementation).toHaveBeenCalledOnce();
  });

  it('reports only triage-delivery stage, HTTP 500, and safe category', async () => {
    const output: string[] = [];
    const errors: string[] = [];
    const fetchImplementation = vi.fn(async (input: Parameters<typeof fetch>[0]) => {
      if (String(input).endsWith('/azure-monitor')) {
        return new Response(JSON.stringify({
          status: 'created', incidentId: 7, messageId: 12, alertState: 'fired',
          analysisId: null, analysisStatus: 'pending', version: 1,
        }), { status: 201 });
      }
      return new Response('raw triage failure and private secret', { status: 500 });
    });
    const code = await runTriageDemo([
      '--diagnose-safe-stage', '--deliver-staging', '--confirm-staging-delivery',
    ], dependencies(output, errors, stagingEnvironment, {
      fetchImplementation: fetchImplementation as unknown as typeof fetch,
    }));
    expect(code).toBe(1);
    expect(output).toEqual([]);
    expect(JSON.parse(errors.join(''))).toEqual({
      stage: 'triage_delivery', httpStatus: 500, category: 'remote',
    });
    expect(errors.join('')).not.toMatch(/raw triage|private secret|taski-staging|synthetic-key/);
    expect(fetchImplementation).toHaveBeenCalledTimes(2);
  });

  it('reports fixed configuration and fixture stages without raw local errors', async () => {
    const configurationOutput: string[] = [];
    const configurationErrors: string[] = [];
    const configurationCode = await runTriageDemo([
      '--diagnose-safe-stage', '--deliver-staging', '--confirm-staging-delivery',
    ], dependencies(configurationOutput, configurationErrors));
    expect(configurationCode).toBe(1);
    expect(JSON.parse(configurationErrors.join(''))).toEqual({ stage: 'configuration' });
    expect(forbiddenNetwork).not.toHaveBeenCalled();

    const fixtureOutput: string[] = [];
    const fixtureErrors: string[] = [];
    const fixtureCode = await runTriageDemo(
      ['--diagnose-safe-stage'],
      dependencies(fixtureOutput, fixtureErrors, {}, {
        readTextFile: async () => { throw new Error('raw fixture secret and private path'); },
      }),
    );
    expect(fixtureCode).toBe(1);
    expect(JSON.parse(fixtureErrors.join(''))).toEqual({ stage: 'fixture' });
    expect(fixtureErrors.join('')).not.toMatch(/raw fixture|private path|secret/);
    expect(forbiddenNetwork).not.toHaveBeenCalled();
  });

  it('normal mode retains the original generic failure output', async () => {
    const output: string[] = [];
    const errors: string[] = [];
    const fetchImplementation = vi.fn(async () => new Response(
      'raw-secret simulated-error https://private.example.invalid', { status: 400 },
    ));
    const code = await runTriageDemo([
      '--deliver-staging', '--confirm-staging-delivery',
    ], dependencies(output, errors, stagingEnvironment, {
      fetchImplementation: fetchImplementation as unknown as typeof fetch,
    }));
    expect(code).toBe(1);
    expect(output).toEqual([]);
    expect(errors).toEqual(['Triage demo failed safely.\n']);
  });

  it('reuses production normalization, pipeline, clients, signing, schemas, and guardrails', async () => {
    const source = await readFile(new URL('../scripts/runTriageDemo.ts', import.meta.url), 'utf8');
    expect(source).toMatch(/normalizeAzureAlert/);
    expect(source).toMatch(/azureMonitorCommonAlertSchema/);
    expect(source).toMatch(/processIncident/);
    expect(source).toMatch(/validateGuardedTriageResult/);
    expect(source).not.toMatch(/createHmac|X-Taski-Signature|\/api\/incidents\/integrations/);
  });
});
