import { Buffer } from 'node:buffer';
import { createHmac } from 'node:crypto';
import type { NormalizedIncident } from '../contracts/normalizedIncident.js';
import { canonicalJson } from '../shared/canonicalJson.js';
import { safeError } from '../shared/safeErrors.js';

export interface TaskiSignatureConfig {
  keyId: string;
  secret: string;
}

export interface SignedTaskiRequest {
  bodyBytes: Buffer;
  headers: Readonly<Record<string, string>>;
  timestamp: number;
}

export function signTaskiBody(
  body: unknown,
  timestamp: number,
  config: TaskiSignatureConfig,
): SignedTaskiRequest {
  const secretBytes = Buffer.from(config.secret, 'utf8');
  if (secretBytes.length < 32 || secretBytes.length > 4_096) throw safeError('configuration');
  if (!config.keyId || config.keyId.length > 128) throw safeError('configuration');
  if (!Number.isSafeInteger(timestamp) || timestamp <= 0) throw safeError('configuration');

  const bodyBytes = Buffer.from(canonicalJson(body), 'utf8');
  const signature = createHmac('sha256', secretBytes)
    .update(Buffer.from(`${timestamp}.`, 'utf8'))
    .update(bodyBytes)
    .digest('hex');
  return {
    bodyBytes,
    timestamp,
    headers: {
      'Content-Type': 'application/json',
      'X-Taski-Key-Id': config.keyId,
      'X-Taski-Timestamp': String(timestamp),
      'X-Taski-Signature': signature,
    },
  };
}

export function signTaskiIncident(
  incident: NormalizedIncident,
  timestamp: number,
  config: TaskiSignatureConfig,
): SignedTaskiRequest {
  return signTaskiBody(incident, timestamp, config);
}
