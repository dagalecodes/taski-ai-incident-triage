import { azureMonitorCommonAlertSchema } from '../contracts/azureMonitor.js';
import { normalizeAzureAlert } from '../alerts/normalizeAzureAlert.js';
import { canonicalJson } from '../shared/canonicalJson.js';

export const MAX_HTTP_REQUEST_BYTES = 256 * 1024;

export interface ReceiverRequest {
  contentType: string | null;
  bodyBytes: Uint8Array;
}

export interface ReceiverDependencies {
  currentTimestamp(): string;
  enqueue(message: string): void;
}

export interface ReceiverResponse {
  status: 202 | 400 | 413 | 415 | 500;
  body: Readonly<Record<string, unknown>>;
}

function jsonContentType(value: string | null): boolean {
  return value !== null && /^application\/json(?:\s*;|$)/i.test(value);
}

export function receiveAlert(
  request: ReceiverRequest,
  dependencies: ReceiverDependencies,
): ReceiverResponse {
  if (!jsonContentType(request.contentType)) {
    return { status: 415, body: { error: 'Unsupported content type.' } };
  }
  if (request.bodyBytes.byteLength > MAX_HTTP_REQUEST_BYTES) {
    return { status: 413, body: { error: 'Alert payload is too large.' } };
  }
  let raw: unknown;
  try {
    raw = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(request.bodyBytes));
  } catch {
    return { status: 400, body: { error: 'Alert validation failed.' } };
  }
  const alert = azureMonitorCommonAlertSchema.safeParse(raw);
  if (!alert.success) return { status: 400, body: { error: 'Alert validation failed.' } };
  try {
    const normalized = normalizeAzureAlert(alert.data, dependencies.currentTimestamp());
    dependencies.enqueue(canonicalJson(normalized));
    return {
      status: 202,
      body: {
        accepted: true,
        externalAlertId: normalized.externalAlertId,
        deliveryId: normalized.deliveryId,
        condition: normalized.condition,
      },
    };
  } catch {
    return { status: 500, body: { error: 'Alert processing failed.' } };
  }
}
