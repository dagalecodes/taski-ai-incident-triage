import { triageResultSchema, type TriageResult } from '../contracts/triageResult.js';
import type { NormalizedIncident } from '../contracts/normalizedIncident.js';

const SECRET_PATTERNS = [
  /\bsk-[A-Za-z0-9_-]{12,}\b/gi,
  /\b(?:bearer|token|password|passwd|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+/gi,
  /\b(?:AccountKey|SharedAccessSignature)\s*=\s*[^;\s]+/gi,
  /\b(?:DefaultEndpointsProtocol|EndpointSuffix|AccountName)=[^;\r\n]+(?:;[^\r\n]+)*/gi,
];
const INJECTION_PATTERNS = [
  /\bignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions?\b/gi,
  /\b(?:system|developer)\s+(?:message|prompt)\s*:/gi,
  /\bdo\s+not\s+follow\s+(?:the\s+)?instructions?\b/gi,
  /\breveal\s+(?:the\s+)?(?:secret|prompt|token|key)\b/gi,
];
const COMMAND_PATTERNS = [
  /```|`[^`]+`/,
  /(?:^|\s)(?:sudo|bash|sh|pwsh|powershell|cmd(?:\.exe)?|curl|wget|kubectl|terraform|az|aws|gcloud)\s+/i,
  /(?:&&|\|\||;\s*(?:sudo|bash|sh|pwsh|powershell|curl|wget|kubectl|az)\b)/i,
  /(?:^|\s)(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\s+\S+/i,
  /\$\([^)]+\)|\$env:|\.\/[A-Za-z0-9_-]+/i,
];

export interface SafeIncidentContext {
  provider: 'azure_monitor';
  externalAlertId: string;
  deliveryId: string;
  severity: NormalizedIncident['severity'];
  alertRule: string;
  affectedService: string;
  targetResourceId: string;
  signalType: string;
  monitoringService: string;
  summary: string;
  occurredAt: string;
}

export interface EvidenceLedgerEntry {
  source: TriageResult['evidence'][number]['source'];
  finding: string;
  reference?: string;
}

export function redactUntrustedText(value: string, maximum = 1_500): string {
  let result = value.slice(0, maximum);
  for (const pattern of SECRET_PATTERNS) result = result.replace(pattern, '[REDACTED]');
  for (const pattern of INJECTION_PATTERNS) {
    result = result.replace(pattern, '[UNTRUSTED_INSTRUCTION_REMOVED]');
  }
  return result.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim();
}

export function containsSensitivePattern(value: string): boolean {
  return SECRET_PATTERNS.some((pattern) => {
    pattern.lastIndex = 0;
    return pattern.test(value);
  });
}

export function sanitizeIncidentContext(incident: NormalizedIncident): SafeIncidentContext {
  return {
    provider: incident.provider,
    externalAlertId: redactUntrustedText(incident.externalAlertId, 2_048),
    deliveryId: incident.deliveryId,
    severity: incident.severity,
    alertRule: redactUntrustedText(incident.alertRule, 512),
    affectedService: redactUntrustedText(incident.affectedService, 256),
    targetResourceId: redactUntrustedText(incident.targetResourceId, 2_048),
    signalType: redactUntrustedText(incident.signalType, 128),
    monitoringService: redactUntrustedText(incident.monitoringService, 128),
    summary: redactUntrustedText(incident.summary, 1_000),
    occurredAt: incident.occurredAt,
  };
}

export function safeEvidenceReference(reference: string | undefined): boolean {
  if (reference === undefined) return true;
  if (!reference || containsSensitivePattern(reference)) return false;
  if (!/^[A-Za-z][A-Za-z0-9+.-]*:/.test(reference)) return true;
  try {
    const url = new URL(reference);
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password;
  } catch {
    return false;
  }
}

export function validateGuardedTriageResult(
  candidate: unknown,
  evidenceLedger: readonly EvidenceLedgerEntry[],
): TriageResult {
  const parsed = triageResultSchema.safeParse(candidate);
  if (!parsed.success) throw new Error('Invalid structured triage result.');
  const serialized = JSON.stringify(parsed.data);
  if (containsSensitivePattern(serialized)) throw new Error('Sensitive triage result rejected.');
  if (parsed.data.recommendedActions.some(({ action }) => COMMAND_PATTERNS.some(pattern => pattern.test(action)))) {
    throw new Error('Executable recommendation rejected.');
  }
  for (const evidence of parsed.data.evidence) {
    if (!safeEvidenceReference(evidence.reference)) throw new Error('Unsafe evidence reference rejected.');
    const supported = evidenceLedger.some(entry => entry.source === evidence.source
      && entry.finding === evidence.finding && entry.reference === evidence.reference);
    if (!supported) throw new Error('Unsupported evidence rejected.');
  }
  return parsed.data;
}
