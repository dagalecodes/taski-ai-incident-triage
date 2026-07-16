import { z } from 'zod';

const environmentSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  TASKI_INTERNAL_BASE_URL: z.string().url().max(2_048).optional(),
  TASKI_INTEGRATION_KEY_ID: z.string().min(1).max(128).optional(),
  TASKI_INTEGRATION_SECRET: z.string().min(16).max(4_096).optional(),
  AZURE_STORAGE_CONNECTION_STRING: z.string().min(1).max(8_192).optional(),
  AZURE_INCIDENT_QUEUE_NAME: z.string().regex(/^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$/).optional(),
  OPENAI_API_KEY: z.string().min(1).max(4_096).optional(),
});

const futureRequiredSettings = [
  'TASKI_INTERNAL_BASE_URL', 'TASKI_INTEGRATION_KEY_ID', 'TASKI_INTEGRATION_SECRET',
  'AZURE_STORAGE_CONNECTION_STRING', 'AZURE_INCIDENT_QUEUE_NAME', 'OPENAI_API_KEY',
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
  options: { requireFutureSettings?: boolean } = {},
): RuntimeEnvironment {
  const parsed = environmentSchema.safeParse(suppliedEnvironment);
  if (!parsed.success) {
    const fields = [...new Set(parsed.error.issues.map((issue) => issue.path.join('.') || 'environment'))];
    throw new ConfigurationError(`Invalid configuration fields: ${fields.join(', ')}.`);
  }
  if (options.requireFutureSettings) {
    const missing = futureRequiredSettings.filter((name) => parsed.data[name] === undefined);
    if (missing.length > 0) throw new ConfigurationError(`Missing required configuration fields: ${missing.join(', ')}.`);
  }
  return parsed.data;
}
