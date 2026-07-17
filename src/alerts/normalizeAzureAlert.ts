import { createHash } from 'node:crypto';
import type { AzureMonitorCommonAlert } from '../contracts/azureMonitor.js';
import { isoTimestampSchema } from '../contracts/azureMonitor.js';
import { normalizedIncidentSchema, type NormalizedIncident } from '../contracts/normalizedIncident.js';
import { canonicalJson } from '../shared/canonicalJson.js';

const severityMap = {
  Sev0: 'critical', Sev1: 'error', Sev2: 'warning', Sev3: 'informational', Sev4: 'verbose',
} as const;

function toUtcIso(value: string): string {
  return new Date(isoTimestampSchema.parse(value)).toISOString();
}

function affectedService(configurationItems: string[] | undefined, targetResourceId: string): string {
  const configured = configurationItems?.[0]?.trim();
  if (configured) return configured;
  const segments = targetResourceId.split('/').filter((segment) => segment.length > 0);
  return segments.at(-1) ?? targetResourceId;
}

function deliveryIdentity(fields: Omit<NormalizedIncident, 'deliveryId' | 'receivedAt'>): string {
  return `sha256:${createHash('sha256').update(canonicalJson(fields)).digest('hex')}`;
}

export function normalizeAzureAlert(alert: AzureMonitorCommonAlert, receivedAt: string): NormalizedIncident {
  const essentials = alert.data.essentials;
  const targetResourceId = essentials.alertTargetIDs[0];
  if (targetResourceId === undefined) throw new Error('A validated Azure alert must contain a target resource ID.');

  const occurredAt = essentials.monitorCondition === 'resolved'
    ? essentials.resolvedDateTime
    : essentials.firedDateTime;
  if (occurredAt === undefined) throw new Error('A resolved Azure alert must contain resolvedDateTime.');

  const stableFields = {
    schemaVersion: 1 as const,
    provider: 'azure_monitor' as const,
    externalAlertId: essentials.alertId,
    condition: essentials.monitorCondition,
    severity: severityMap[essentials.severity],
    alertRule: essentials.alertRule,
    affectedService: affectedService(essentials.configurationItems, targetResourceId),
    targetResourceId,
    signalType: essentials.signalType,
    monitoringService: essentials.monitoringService,
    summary: essentials.description ?? essentials.alertRule,
    occurredAt: toUtcIso(occurredAt),
  };

  return normalizedIncidentSchema.parse({
    ...stableFields,
    deliveryId: deliveryIdentity(stableFields),
    receivedAt: toUtcIso(receivedAt),
  });
}
