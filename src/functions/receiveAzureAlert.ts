import { app, output, type HttpRequest, type HttpResponseInit, type InvocationContext } from '@azure/functions';
import { MAX_HTTP_REQUEST_BYTES, receiveAlert } from '../pipeline/receiveAlert.js';

export const incidentQueueOutput = output.storageQueue({
  queueName: '%AZURE_INCIDENT_QUEUE_NAME%',
  connection: 'AzureWebJobsStorage',
});

async function boundedBody(request: HttpRequest): Promise<Uint8Array | null> {
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_HTTP_REQUEST_BYTES) return null;
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const part = await reader.read();
    if (part.done) break;
    const chunk = new Uint8Array(part.value);
    size += chunk.byteLength;
    if (size > MAX_HTTP_REQUEST_BYTES) {
      await reader.cancel();
      return null;
    }
    chunks.push(chunk);
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

export async function receiveAzureAlertHandler(
  request: HttpRequest,
  context: InvocationContext,
): Promise<HttpResponseInit> {
  const contentType = request.headers.get('content-type');
  let bodyBytes: Uint8Array;
  let validationCategories: readonly string[] = [];
  try {
    const bounded = await boundedBody(request);
    if (bounded === null) return { status: 413, jsonBody: { error: 'Alert payload is too large.' } };
    bodyBytes = bounded;
  } catch {
    context.error('Azure alert receiver failed.', { category: 'unexpected' });
    return { status: 500, jsonBody: { error: 'Alert processing failed.' } };
  }
  const response = receiveAlert(
    { contentType, bodyBytes },
    {
      currentTimestamp: () => new Date().toISOString(),
      enqueue: (message) => context.extraOutputs.set(incidentQueueOutput, message),
      reportValidationCategories: (categories) => { validationCategories = categories; },
    },
  );
  if (response.status === 202) {
    context.info('Azure alert accepted.', {
      deliveryId: response.body.deliveryId,
      condition: response.body.condition,
    });
  } else {
    const category = `http_${response.status}`;
    if (response.status === 400 && validationCategories.length > 0) {
      context.warn('Azure alert rejected.', { category, validationCategories });
    } else {
      context.warn('Azure alert rejected.', { category });
    }
  }
  return { status: response.status, jsonBody: response.body };
}

app.http('receiveAzureAlert', {
  route: 'alerts/azure-monitor',
  methods: ['POST'],
  authLevel: 'function',
  extraOutputs: [incidentQueueOutput],
  handler: receiveAzureAlertHandler,
});
