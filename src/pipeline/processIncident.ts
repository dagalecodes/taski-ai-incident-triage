import { normalizedIncidentSchema, type NormalizedIncident } from '../contracts/normalizedIncident.js';
import { sendTaskiIncident, type TaskiIncidentResponse } from '../integrations/taskiClient.js';
import { signTaskiIncident } from '../security/taskiSignature.js';
import { safeError } from '../shared/safeErrors.js';

const MAX_QUEUE_MESSAGE_BYTES = 64 * 1024;

export interface ProcessorConfig {
  taskiBaseUrl: string;
  keyId: string;
  secret: string;
  timeoutMs: number;
}

export interface ProcessorDependencies {
  fetchImplementation: typeof fetch;
  currentEpochSeconds(): number;
}

export interface ProcessedIncident {
  incident: NormalizedIncident;
  result: TaskiIncidentResponse;
}

function parseQueueMessage(message: unknown): unknown {
  if (typeof message !== 'string') return message;
  if (Buffer.byteLength(message, 'utf8') > MAX_QUEUE_MESSAGE_BYTES) throw safeError('invalid_message');
  try {
    return JSON.parse(message);
  } catch {
    throw safeError('invalid_message');
  }
}

export async function processIncident(
  queueMessage: unknown,
  config: ProcessorConfig,
  dependencies: ProcessorDependencies,
): Promise<ProcessedIncident> {
  const validated = normalizedIncidentSchema.safeParse(parseQueueMessage(queueMessage));
  if (!validated.success) throw safeError('invalid_message');
  const signed = signTaskiIncident(validated.data, dependencies.currentEpochSeconds(), {
    keyId: config.keyId, secret: config.secret,
  });
  const result = await sendTaskiIncident(signed, {
    baseUrl: config.taskiBaseUrl,
    timeoutMs: config.timeoutMs,
    fetchImplementation: dependencies.fetchImplementation,
  });
  return { incident: validated.data, result };
}
