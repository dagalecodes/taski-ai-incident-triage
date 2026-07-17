import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { taskiTriageResultSchema } from '../src/contracts/taskiTriageResult.js';

describe('one-agent SDK configuration', () => {
  it('uses one Agent, the existing output schema, bounded run controls, and privacy-safe tracing', async () => {
    const source = await readFile(new URL('../src/agent/triageAgent.ts', import.meta.url), 'utf8');
    expect(source.match(/new Agent\s*\(/g)).toHaveLength(1);
    expect(source).toContain('outputType: triageResultSchema');
    expect(source).toContain('maxTurns: config.maxTurns');
    expect(source).toContain('signal: controller.signal');
    expect(source).toContain('tracingDisabled: !config.tracingEnabled');
    expect(source).toContain('traceIncludeSensitiveData: false');
    expect(source).not.toMatch(/handoffs\s*:|mcpServers\s*:|shellTool\s*\(|computerTool\s*\(|codeInterpreterTool\s*\(/);
  });

  it('keeps the Taski envelope on the authoritative Batch 1 diagnosis schema', () => {
    const base = {
      schemaVersion: 1, incidentId: 7, provider: 'azure_monitor', externalAlertId: 'synthetic-alert',
      sourceDeliveryId: `sha256:${'a'.repeat(64)}`, analysisStatus: 'completed',
      analysisId: `analysis:policy-v1:${'b'.repeat(64)}`, failure: null,
      completedAt: '2026-07-16T10:01:00.000Z',
    };
    const diagnosis = {
      schemaVersion: 1, classification: 'unknown', probableCause: 'Insufficient fixture evidence.',
      confidence: 0.2, evidence: [],
      recommendedActions: [{ action: 'Review the incident manually.', requiresHumanApproval: true }],
      limitations: ['Diagnostic providers were unavailable.'],
    };
    expect(taskiTriageResultSchema.safeParse({ ...base, diagnosis }).success).toBe(true);
    expect(taskiTriageResultSchema.safeParse({
      ...base, diagnosis: { ...diagnosis, summary: 'Conflicting field' },
    }).success).toBe(false);
  });
});
