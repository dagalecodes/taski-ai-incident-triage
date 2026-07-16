import { z } from 'zod';
import { triageResultSchema } from './triageResult.js';

const deliveryIdSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const analysisIdSchema = z.string().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
const completedAtSchema = z.string().datetime({ offset: false });

const correlationSchema = z.object({
  schemaVersion: z.literal(1),
  incidentId: z.number().int().positive().max(2_147_483_647),
  provider: z.literal('azure_monitor'),
  externalAlertId: z.string().trim().min(1).max(2_048),
  sourceDeliveryId: deliveryIdSchema,
  analysisId: analysisIdSchema,
  completedAt: completedAtSchema,
});

export const taskiCompletedTriageResultSchema = correlationSchema.extend({
  analysisStatus: z.literal('completed'),
  diagnosis: triageResultSchema,
  failure: z.null(),
}).strict();

export const taskiFailedTriageResultSchema = correlationSchema.extend({
  analysisStatus: z.literal('failed'),
  diagnosis: z.null(),
  failure: z.object({
    code: z.enum(['timeout', 'model_unavailable', 'invalid_result', 'internal_error']),
  }).strict(),
}).strict();

export const taskiTriageResultSchema = z.discriminatedUnion('analysisStatus', [
  taskiCompletedTriageResultSchema,
  taskiFailedTriageResultSchema,
]);

export type TaskiTriageResult = z.infer<typeof taskiTriageResultSchema>;
