import { describe, expect, it } from 'vitest';
import { triageResultSchema } from '../src/contracts/triageResult.js';

function validResult() {
  return {
    schemaVersion: 1,
    classification: 'availability',
    probableCause: 'The demo API health endpoint is unavailable.',
    confidence: 0.85,
    evidence: [{ source: 'service_health', finding: 'Three bounded health checks failed.', reference: 'demo-health-check' }],
    recommendedActions: [{ action: 'Review the demo API health state.', requiresHumanApproval: true }],
    limitations: ['No production resources were inspected.'],
  };
}

describe('triage result contract', () => {
  it('accepts a valid strict result', () => expect(triageResultSchema.safeParse(validResult()).success).toBe(true));

  it('rejects unknown top-level and nested executable fields', () => {
    expect(triageResultSchema.safeParse({ ...validResult(), chainOfThought: 'hidden reasoning' }).success).toBe(false);
    const command = { ...validResult(), recommendedActions: [{ ...validResult().recommendedActions[0], command: 'do-not-run' }] };
    expect(triageResultSchema.safeParse(command).success).toBe(false);
    const script = { ...validResult(), evidence: [{ ...validResult().evidence[0], script: 'do-not-run' }] };
    expect(triageResultSchema.safeParse(script).success).toBe(false);
    const toolArguments = { ...validResult(), recommendedActions: [{ ...validResult().recommendedActions[0], toolArguments: {} }] };
    expect(triageResultSchema.safeParse(toolArguments).success).toBe(false);
  });

  it('rejects invalid confidence and high confidence without evidence', () => {
    expect(triageResultSchema.safeParse({ ...validResult(), confidence: 1.1 }).success).toBe(false);
    expect(triageResultSchema.safeParse({ ...validResult(), confidence: 0.8, evidence: [] }).success).toBe(false);
  });

  it('rejects unsupported sources, excessive arrays, and non-approved actions', () => {
    expect(triageResultSchema.safeParse({ ...validResult(), evidence: [{ source: 'shell', finding: 'Unsafe.' }] }).success).toBe(false);
    expect(triageResultSchema.safeParse({ ...validResult(), limitations: Array.from({ length: 11 }, () => 'Bounded item') }).success).toBe(false);
    expect(triageResultSchema.safeParse({ ...validResult(), recommendedActions: [{ action: 'Act automatically.', requiresHumanApproval: false }] }).success).toBe(false);
  });
});
