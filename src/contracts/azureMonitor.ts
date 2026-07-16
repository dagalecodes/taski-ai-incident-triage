import { z } from 'zod';
import { canonicalJson } from '../shared/canonicalJson.js';

const MAX_ALERT_JSON_CHARS = 256 * 1024;
const MAX_CONTEXT_JSON_CHARS = 32 * 1024;

function boundedText(maximum: number) {
  return z.string().trim().min(1).max(maximum);
}

function isValidIsoTimestamp(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$/.exec(value);
  if (!match) return false;
  const [yearText, monthText, dayText, hourText, minuteText, secondText, offsetHourText, offsetMinuteText] = match.slice(1);
  if (!yearText || !monthText || !dayText || !hourText || !minuteText || !secondText) return false;
  const [year, month, day, hour, minute, second] = [
    yearText, monthText, dayText, hourText, minuteText, secondText,
  ].map(Number);
  if (year === undefined || month === undefined || day === undefined
    || hour === undefined || minute === undefined || second === undefined) return false;
  const offsetHour = offsetHourText === undefined ? 0 : Number(offsetHourText);
  const offsetMinute = offsetMinuteText === undefined ? 0 : Number(offsetMinuteText);
  if (hour > 23 || minute > 59 || second > 59) return false;
  if ((offsetHour ?? 0) > 23 || (offsetMinute ?? 0) > 59) return false;
  const calendarDate = new Date(Date.UTC(year, month - 1, day));
  return calendarDate.getUTCFullYear() === year
    && calendarDate.getUTCMonth() === month - 1
    && calendarDate.getUTCDate() === day
    && !Number.isNaN(Date.parse(value));
}

export const isoTimestampSchema = z.string().trim().max(64).refine(
  isValidIsoTimestamp,
  'Expected a valid ISO-8601 timestamp with a timezone.',
);

const monitorConditionSchema = boundedText(32)
  .transform((value) => value.toLowerCase())
  .pipe(z.enum(['fired', 'resolved']));

const boundedProviderObjectSchema = z.record(z.string().min(1).max(128), z.unknown()).superRefine((value, context) => {
  try {
    if (canonicalJson(value).length > MAX_CONTEXT_JSON_CHARS) {
      context.addIssue({ code: 'custom', message: 'Provider object is too large.' });
    }
  } catch {
    context.addIssue({ code: 'custom', message: 'Provider object must contain JSON-compatible values.' });
  }
});

const essentialsSchema = z.object({
  alertId: boundedText(2_048),
  alertRule: boundedText(512),
  severity: z.enum(['Sev0', 'Sev1', 'Sev2', 'Sev3', 'Sev4']),
  signalType: boundedText(128),
  monitorCondition: monitorConditionSchema,
  monitoringService: boundedText(128),
  firedDateTime: isoTimestampSchema,
  resolvedDateTime: isoTimestampSchema.optional(),
  alertTargetIDs: z.array(boundedText(2_048)).min(1).max(20),
  description: boundedText(1_000).optional(),
  configurationItems: z.array(boundedText(256)).max(50).optional(),
}).passthrough().superRefine((value, context) => {
  if (value.monitorCondition === 'resolved' && value.resolvedDateTime === undefined) {
    context.addIssue({
      code: 'custom',
      message: 'resolvedDateTime is required for resolved alerts.',
      path: ['resolvedDateTime'],
    });
  }
});

export const azureMonitorCommonAlertSchema = z.object({
  schemaId: z.literal('azureMonitorCommonAlertSchema'),
  data: z.object({
    essentials: essentialsSchema,
    alertContext: boundedProviderObjectSchema.optional(),
    customProperties: boundedProviderObjectSchema.optional(),
  }).passthrough(),
}).passthrough().superRefine((value, context) => {
  try {
    if (canonicalJson(value).length > MAX_ALERT_JSON_CHARS) {
      context.addIssue({ code: 'custom', message: 'Alert payload is too large.' });
    }
  } catch {
    context.addIssue({ code: 'custom', message: 'Alert payload must contain JSON-compatible values.' });
  }
});

export type AzureMonitorCommonAlert = z.infer<typeof azureMonitorCommonAlertSchema>;
