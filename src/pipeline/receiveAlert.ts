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
  reportValidationCategories?(categories: readonly AlertValidationCategory[]): void;
}

export interface ReceiverResponse {
  status: 202 | 400 | 413 | 415 | 500;
  body: Readonly<Record<string, unknown>>;
}

export const alertValidationCategories = [
  'schemaId',
  'data.essentials',
  'data.alertContext',
  'data.customProperties',
  'payload',
  'other',
] as const;

export type AlertValidationCategory = typeof alertValidationCategories[number];

const MAX_VALIDATION_CATEGORIES = 5;

function validationCategory(path: readonly PropertyKey[]): AlertValidationCategory {
  if (path.length === 0) return 'payload';
  if (path[0] === 'schemaId') return 'schemaId';
  if (path[0] !== 'data') return 'other';
  if (path[1] === 'essentials') return 'data.essentials';
  if (path[1] === 'alertContext') return 'data.alertContext';
  if (path[1] === 'customProperties') return 'data.customProperties';
  return 'other';
}

function reportValidationCategories(
  dependencies: ReceiverDependencies,
  categories: readonly AlertValidationCategory[],
): void {
  if (!dependencies.reportValidationCategories) return;
  const safeCategories = [...new Set(categories)].slice(0, MAX_VALIDATION_CATEGORIES);
  try {
    dependencies.reportValidationCategories(safeCategories);
  } catch {
    // Optional diagnostics must never change receiver behavior.
  }
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
    reportValidationCategories(dependencies, ['payload']);
    return { status: 400, body: { error: 'Alert validation failed.' } };
  }
  const alert = azureMonitorCommonAlertSchema.safeParse(raw);
  if (!alert.success) {
    reportValidationCategories(dependencies, alert.error.issues.map((issue) => validationCategory(issue.path)));
    return { status: 400, body: { error: 'Alert validation failed.' } };
  }
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
