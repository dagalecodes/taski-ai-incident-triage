import { normalizedIncidentSchema, type NormalizedIncident } from '../contracts/normalizedIncident.js';
import { taskiTriageResultSchema, type TaskiTriageResult } from '../contracts/taskiTriageResult.js';
import { triageResultSchema } from '../contracts/triageResult.js';
import {
  sendTaskiIncident,
  sendTaskiTriageResult,
  type TaskiIncidentResponse,
  type TaskiTriageResponse,
} from '../integrations/taskiClient.js';
import { signTaskiBody, signTaskiIncident } from '../security/taskiSignature.js';
import { createHash } from 'node:crypto';
import { SafeTriageError, type TriageRunner } from '../agent/triageAgent.js';
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
  currentIsoTimestamp(): string;
  resolveTriagePolicyVersion?(): string;
  createTriageRunner?(): TriageRunner;
}

export interface ProcessedIncident {
  incident: NormalizedIncident;
  result: TaskiIncidentResponse;
  triageResult?: TaskiTriageResult;
  triageDelivery?: TaskiTriageResponse;
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
  if (validated.data.condition === 'resolved' || result.alertState === 'resolved'
    || result.status === 'stale') {
    return { incident: validated.data, result };
  }

  let analysisId: string;
  try {
    if (!dependencies.resolveTriagePolicyVersion) throw new Error('Missing triage identity resolver.');
    analysisId = deterministicAnalysisId(validated.data, dependencies.resolveTriagePolicyVersion());
  } catch {
    throw safeError('configuration');
  }
  if (result.analysisId === analysisId
    && ['ready', 'failed', 'not_required'].includes(result.analysisStatus)) {
    return { incident: validated.data, result };
  }

  let triageResult: TaskiTriageResult;
  try {
    let triageRunner: TriageRunner;
    try {
      if (!dependencies.createTriageRunner) throw new Error('Missing triage runner factory.');
      triageRunner = dependencies.createTriageRunner();
    } catch {
      throw new SafeTriageError('model_unavailable');
    }
    const diagnosis = triageResultSchema.parse(await triageRunner.run(validated.data));
    triageResult = taskiTriageResultSchema.parse({
      schemaVersion: 1,
      incidentId: result.incidentId,
      provider: validated.data.provider,
      externalAlertId: validated.data.externalAlertId,
      sourceDeliveryId: validated.data.deliveryId,
      analysisStatus: 'completed',
      analysisId,
      diagnosis,
      failure: null,
      completedAt: dependencies.currentIsoTimestamp(),
    });
  } catch (error) {
    const code = error instanceof SafeTriageError ? error.code : 'invalid_result';
    triageResult = taskiTriageResultSchema.parse({
      schemaVersion: 1,
      incidentId: result.incidentId,
      provider: validated.data.provider,
      externalAlertId: validated.data.externalAlertId,
      sourceDeliveryId: validated.data.deliveryId,
      analysisStatus: 'failed',
      analysisId,
      diagnosis: null,
      failure: { code },
      completedAt: dependencies.currentIsoTimestamp(),
    });
  }
  const signedTriage = signTaskiBody(triageResult, dependencies.currentEpochSeconds(), {
    keyId: config.keyId, secret: config.secret,
  });
  const triageDelivery = await sendTaskiTriageResult(signedTriage, {
    baseUrl: config.taskiBaseUrl,
    timeoutMs: config.timeoutMs,
    fetchImplementation: dependencies.fetchImplementation,
  });
  return { incident: validated.data, result, triageResult, triageDelivery };
}

export function deterministicAnalysisId(
  incident: NormalizedIncident,
  policyVersion: string,
): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,47}$/.test(policyVersion)) throw safeError('configuration');
  const digest = createHash('sha256').update(JSON.stringify({
    provider: incident.provider,
    externalAlertId: incident.externalAlertId,
    sourceDeliveryId: incident.deliveryId,
    policyVersion,
  })).digest('hex');
  return `analysis:${policyVersion}:${digest}`;
}
