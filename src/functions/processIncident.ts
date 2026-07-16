import { app, type InvocationContext } from '@azure/functions';
import { validateEnvironment } from '../config/env.js';
import { processIncident } from '../pipeline/processIncident.js';
import { SafePipelineError, safeError } from '../shared/safeErrors.js';

export async function processIncidentHandler(message: unknown, context: InvocationContext): Promise<void> {
  try {
    const environment = validateEnvironment(process.env, { requirePipelineSettings: true });
    if (!environment.TASKI_INTERNAL_BASE_URL || !environment.TASKI_INCIDENT_KEY_ID
      || !environment.TASKI_INCIDENT_SECRET) throw safeError('configuration');
    const processed = await processIncident(
      message,
      {
        taskiBaseUrl: environment.TASKI_INTERNAL_BASE_URL,
        keyId: environment.TASKI_INCIDENT_KEY_ID,
        secret: environment.TASKI_INCIDENT_SECRET,
        timeoutMs: environment.TASKI_REQUEST_TIMEOUT_MS,
      },
      {
        fetchImplementation: fetch,
        currentEpochSeconds: () => Math.floor(Date.now() / 1_000),
      },
    );
    context.info('Incident forwarded to Taski.', {
      deliveryId: processed.incident.deliveryId,
      condition: processed.incident.condition,
      status: processed.result.status,
      incidentId: processed.result.incidentId,
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
