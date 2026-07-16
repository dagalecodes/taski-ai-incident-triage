import { Buffer } from 'node:buffer';
import { z } from 'zod';

const queueNameSchema = z.string().min(3).max(63)
  .regex(/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])$/)
  .refine((value) => !value.includes('--'));

const taskiUrlSchema = z.string().url().max(2_048).superRefine((value, context) => {
  const url = new URL(value);
  const localhost = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol !== 'https:' && !(localhost && url.protocol === 'http:')) {
    context.addIssue({ code: 'custom', message: 'Expected HTTPS or explicit localhost HTTP.' });
  }
  if (url.username || url.password || url.search || url.hash) {
    context.addIssue({ code: 'custom', message: 'Credentials, query, and fragment are not allowed.' });
  }
});

const environmentSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  AzureWebJobsStorage: z.string().min(1).max(8_192).optional(),
  AZURE_INCIDENT_QUEUE_NAME: queueNameSchema.optional(),
  TASKI_INTERNAL_BASE_URL: taskiUrlSchema.optional(),
  TASKI_INCIDENT_KEY_ID: z.string().min(1).max(128).optional(),
  TASKI_INCIDENT_SECRET: z.string().refine((value) => {
    const bytes = Buffer.byteLength(value, 'utf8');
    return bytes >= 32 && bytes <= 4_096;
  }).optional(),
  TASKI_REQUEST_TIMEOUT_MS: z.string().regex(/^\d+$/).optional()
    .transform((value) => Number(value ?? '10000'))
    .pipe(z.number().int().min(1_000).max(30_000)),
}).strict();

const pipelineSettings = [
  'AzureWebJobsStorage', 'AZURE_INCIDENT_QUEUE_NAME', 'TASKI_INTERNAL_BASE_URL',
  'TASKI_INCIDENT_KEY_ID', 'TASKI_INCIDENT_SECRET',
] as const;

export type RuntimeEnvironment = z.infer<typeof environmentSchema>;

export class ConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigurationError';
  }
}

export function validateEnvironment(
  suppliedEnvironment: Readonly<Record<string, string | undefined>>,
  options: { requirePipelineSettings?: boolean } = {},
): RuntimeEnvironment {
  const recognized = Object.fromEntries(
    Object.entries(suppliedEnvironment).filter(([key]) => key in environmentSchema.shape),
  );
  const parsed = environmentSchema.safeParse(recognized);
  if (!parsed.success) {
    const fields = [...new Set(parsed.error.issues.map((issue) => issue.path.join('.') || 'environment'))];
    throw new ConfigurationError(`Invalid configuration fields: ${fields.join(', ')}.`);
  }
  if (options.requirePipelineSettings) {
    const missing = pipelineSettings.filter((name) => parsed.data[name] === undefined);
    if (missing.length > 0) throw new ConfigurationError(`Missing required configuration fields: ${missing.join(', ')}.`);
  }
  return parsed.data;
}
