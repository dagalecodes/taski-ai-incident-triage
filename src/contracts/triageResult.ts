import { z } from 'zod';

export const HIGH_CONFIDENCE_THRESHOLD = 0.7;

const evidenceSchema = z.object({
  source: z.enum(['service_health', 'recent_errors', 'resource_metrics', 'latest_deployment', 'runbook']),
  finding: z.string().trim().min(1).max(1_500),
  reference: z.string().trim().min(1).max(512).optional(),
}).strict();

const recommendedActionSchema = z.object({
  action: z.string().trim().min(1).max(1_000),
  requiresHumanApproval: z.literal(true),
}).strict();

export const triageResultSchema = z.object({
  schemaVersion: z.literal(1),
  classification: z.enum(['availability', 'performance', 'dependency', 'deployment', 'security', 'unknown']),
  probableCause: z.string().trim().min(1).max(2_000),
  confidence: z.number().min(0).max(1),
  evidence: z.array(evidenceSchema).max(10),
  recommendedActions: z.array(recommendedActionSchema).min(1).max(10),
  limitations: z.array(z.string().trim().min(1).max(500)).max(10),
}).strict().superRefine((value, context) => {
  if (value.confidence > HIGH_CONFIDENCE_THRESHOLD && value.evidence.length === 0) {
    context.addIssue({
      code: 'custom',
      message: `Evidence is required when confidence is above ${HIGH_CONFIDENCE_THRESHOLD}.`,
      path: ['evidence'],
    });
  }
});

export type TriageResult = z.infer<typeof triageResultSchema>;
