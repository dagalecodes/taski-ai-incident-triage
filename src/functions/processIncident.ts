import { app, type InvocationContext } from '@azure/functions';
import {
  validateOpenAIEnvironment,
  validateTaskiEnvironment,
  validateTriageIdentityEnvironment,
} from '../config/env.js';
import { processIncident } from '../pipeline/processIncident.js';
import { SafePipelineError, safeError } from '../shared/safeErrors.js';
import { createOpenAITriageRunner } from '../agent/triageAgent.js';
import { createUnavailableDiagnosticProvider } from '../diagnostics/tools.js';

export async function processIncidentHandler(message: unknown, context: InvocationContext): Promise<void> {
  try {
    let taskiEnvironment;
    try {
      taskiEnvironment = validateTaskiEnvironment(process.env);
    } catch {
      throw safeError('configuration');
    }
    const processed = await processIncident(
      message,
      {
        taskiBaseUrl: taskiEnvironment.TASKI_INTERNAL_BASE_URL,
        keyId: taskiEnvironment.TASKI_INCIDENT_KEY_ID,
        secret: taskiEnvironment.TASKI_INCIDENT_SECRET,
        timeoutMs: taskiEnvironment.TASKI_REQUEST_TIMEOUT_MS,
      },
      {
        fetchImplementation: fetch,
        currentEpochSeconds: () => Math.floor(Date.now() / 1_000),
        currentIsoTimestamp: () => new Date().toISOString(),
        resolveTriagePolicyVersion: () => {
          try {
            return validateTriageIdentityEnvironment(process.env).TRIAGE_POLICY_VERSION;
          } catch {
            throw safeError('configuration');
          }
        },
        createTriageRunner: () => {
          const openAI = validateOpenAIEnvironment(process.env);
          return createOpenAITriageRunner({
            apiKey: openAI.OPENAI_API_KEY,
            model: openAI.OPENAI_MODEL,
            timeoutMs: openAI.OPENAI_REQUEST_TIMEOUT_MS,
            maxTurns: openAI.OPENAI_MAX_TURNS,
            tracingEnabled: openAI.OPENAI_TRACING_ENABLED,
          }, createUnavailableDiagnosticProvider());
        },
      },
    );
    context.info('Incident forwarded to Taski.', {
      deliveryId: processed.incident.deliveryId,
      condition: processed.incident.condition,
      status: processed.result.status,
      incidentId: processed.result.incidentId,
      triageStatus: processed.triageResult?.analysisStatus ?? 'skipped',
    });
  } catch (error) {
    const category = error instanceof SafePipelineError ? error.category : 'configuration';
    context.error('Incident processing failed.', { category });
    throw error;
  }
}

app.storageQueue('processIncident', {
  queueName: '%AZURE_INCIDENT_QUEUE_NAME%',
  connection: 'AzureWebJobsStorage',
  handler: processIncidentHandler,
});
