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
  OPENAI_API_KEY: z.string().min(20).max(4_096).optional(),
  OPENAI_MODEL: z.string().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/).optional(),
  OPENAI_REQUEST_TIMEOUT_MS: z.string().regex(/^\d+$/).optional()
    .transform((value) => Number(value ?? '30000'))
    .pipe(z.number().int().min(1_000).max(120_000)),
  OPENAI_MAX_TURNS: z.string().regex(/^\d+$/).optional()
    .transform((value) => Number(value ?? '6'))
    .pipe(z.number().int().min(1).max(8)),
  OPENAI_TRACING_ENABLED: z.enum(['true', 'false']).optional()
    .transform((value) => value === 'true'),
  TRIAGE_POLICY_VERSION: z.string().min(1).max(48)
    .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/).optional(),
}).strict();

const pipelineSettings = [
  'AzureWebJobsStorage', 'AZURE_INCIDENT_QUEUE_NAME', 'TASKI_INTERNAL_BASE_URL',
  'TASKI_INCIDENT_KEY_ID', 'TASKI_INCIDENT_SECRET',
  'OPENAI_API_KEY', 'OPENAI_MODEL', 'TRIAGE_POLICY_VERSION',
] as const;

const taskiSettingsSchema = environmentSchema.pick({
  TASKI_INTERNAL_BASE_URL: true,
  TASKI_INCIDENT_KEY_ID: true,
  TASKI_INCIDENT_SECRET: true,
  TASKI_REQUEST_TIMEOUT_MS: true,
}).required({
  TASKI_INTERNAL_BASE_URL: true,
  TASKI_INCIDENT_KEY_ID: true,
  TASKI_INCIDENT_SECRET: true,
});

const triageIdentitySchema = environmentSchema.pick({ TRIAGE_POLICY_VERSION: true }).required();

const openAIExecutionSchema = environmentSchema.pick({
  OPENAI_API_KEY: true,
  OPENAI_MODEL: true,
  OPENAI_REQUEST_TIMEOUT_MS: true,
  OPENAI_MAX_TURNS: true,
  OPENAI_TRACING_ENABLED: true,
}).required({ OPENAI_API_KEY: true, OPENAI_MODEL: true });

export type RuntimeEnvironment = z.infer<typeof environmentSchema>;

export class ConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigurationError';
  }
}

function recognizedValues(
  suppliedEnvironment: Readonly<Record<string, string | undefined>>,
  fields: ReadonlySet<string>,
): Record<string, string | undefined> {
  return Object.fromEntries(Object.entries(suppliedEnvironment).filter(([key]) => fields.has(key)));
}

function configurationError(error: z.ZodError): ConfigurationError {
  const fields = [...new Set(error.issues.map((issue) => issue.path.join('.') || 'environment'))];
  return new ConfigurationError(`Invalid configuration fields: ${fields.join(', ')}.`);
}

export function validateTaskiEnvironment(
  suppliedEnvironment: Readonly<Record<string, string | undefined>>,
): z.infer<typeof taskiSettingsSchema> {
  const parsed = taskiSettingsSchema.safeParse(recognizedValues(
    suppliedEnvironment, new Set(Object.keys(taskiSettingsSchema.shape)),
  ));
  if (!parsed.success) throw configurationError(parsed.error);
  return parsed.data;
}

export function validateTriageIdentityEnvironment(
  suppliedEnvironment: Readonly<Record<string, string | undefined>>,
): z.infer<typeof triageIdentitySchema> {
  const parsed = triageIdentitySchema.safeParse(recognizedValues(
    suppliedEnvironment, new Set(Object.keys(triageIdentitySchema.shape)),
  ));
  if (!parsed.success) throw configurationError(parsed.error);
  return parsed.data;
}

export function validateOpenAIEnvironment(
  suppliedEnvironment: Readonly<Record<string, string | undefined>>,
): z.infer<typeof openAIExecutionSchema> {
  const parsed = openAIExecutionSchema.safeParse(recognizedValues(
    suppliedEnvironment, new Set(Object.keys(openAIExecutionSchema.shape)),
  ));
  if (!parsed.success) throw configurationError(parsed.error);
  return parsed.data;
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
    throw configurationError(parsed.error);
  }
  if (options.requirePipelineSettings) {
    const missing = pipelineSettings.filter((name) => parsed.data[name] === undefined);
    if (missing.length > 0) throw new ConfigurationError(`Missing required configuration fields: ${missing.join(', ')}.`);
  }
  return parsed.data;
}
