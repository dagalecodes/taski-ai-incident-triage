import { z } from 'zod';
import type { SignedTaskiRequest } from '../security/taskiSignature.js';
import { SafePipelineError, safeError } from '../shared/safeErrors.js';

const MAX_RESPONSE_BYTES = 64 * 1024;

const taskiResponseSchema = z.object({
  status: z.enum(['created', 'updated', 'duplicate', 'stale']),
  incidentId: z.number().int().positive(),
  messageId: z.number().int().positive(),
  alertState: z.enum(['fired', 'resolved']),
  version: z.number().int().positive(),
}).strict();

export type TaskiIncidentResponse = z.infer<typeof taskiResponseSchema>;

export interface TaskiClientOptions {
  baseUrl: string;
  timeoutMs: number;
  fetchImplementation: typeof fetch;
}

export function taskiIncidentUrl(baseUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw safeError('configuration');
  }
  const localhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1'
    || parsed.hostname === '[::1]';
  if ((parsed.protocol !== 'https:' && !(localhost && parsed.protocol === 'http:'))
    || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw safeError('configuration');
  }
  const normalized = parsed.toString().replace(/\/+$/, '');
  return `${normalized}/api/incidents/integrations/azure-monitor`;
}

async function readBoundedResponse(response: Response): Promise<string> {
  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) throw safeError('remote');
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const part = await reader.read();
    if (part.done) break;
    size += part.value.byteLength;
    if (size > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw safeError('remote');
    }
    chunks.push(part.value);
  }
  const combined = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(combined);
}

export async function sendTaskiIncident(
  signed: SignedTaskiRequest,
  options: TaskiClientOptions,
): Promise<TaskiIncidentResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs);
  try {
    const response = await options.fetchImplementation(taskiIncidentUrl(options.baseUrl), {
      method: 'POST', headers: signed.headers, body: Uint8Array.from(signed.bodyBytes),
      redirect: 'manual', signal: controller.signal,
    });
    if (!response.ok) throw safeError('remote');
    let body: unknown;
    try {
      body = JSON.parse(await readBoundedResponse(response));
    } catch (error) {
      if (error instanceof SafePipelineError) throw error;
      if (controller.signal.aborted || (error instanceof Error && error.name === 'AbortError')) throw error;
      throw safeError('remote');
    }
    const parsed = taskiResponseSchema.safeParse(body);
    if (!parsed.success) throw safeError('remote');
    return parsed.data;
  } catch (error) {
    if (error instanceof SafePipelineError) throw error;
    if (controller.signal.aborted || (error instanceof Error && error.name === 'AbortError')) {
      throw safeError('timeout');
    }
    throw safeError('network');
  } finally {
    clearTimeout(timeout);
  }
}
