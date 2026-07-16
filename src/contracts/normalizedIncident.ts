import { z } from 'zod';
import { isoTimestampSchema } from './azureMonitor.js';

export const incidentConditionSchema = z.enum(['fired', 'resolved']);
export const incidentSeveritySchema = z.enum(['critical', 'error', 'warning', 'informational', 'verbose']);

export const normalizedIncidentSchema = z.object({
  schemaVersion: z.literal(1),
  provider: z.literal('azure_monitor'),
  externalAlertId: z.string().min(1).max(2_048),
  deliveryId: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  condition: incidentConditionSchema,
  severity: incidentSeveritySchema,
  alertRule: z.string().min(1).max(512),
  affectedService: z.string().min(1).max(256),
  targetResourceId: z.string().min(1).max(2_048),
  signalType: z.string().min(1).max(128),
  monitoringService: z.string().min(1).max(128),
  summary: z.string().min(1).max(1_000),
  occurredAt: isoTimestampSchema,
  receivedAt: isoTimestampSchema,
}).strict();

export type NormalizedIncident = z.infer<typeof normalizedIncidentSchema>;
