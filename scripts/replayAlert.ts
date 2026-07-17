import { readFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { normalizeAzureAlert } from '../src/alerts/normalizeAzureAlert.js';
import { azureMonitorCommonAlertSchema } from '../src/contracts/azureMonitor.js';

const MAX_FIXTURE_BYTES = 256 * 1024;

export interface ReplayDependencies {
  readTextFile(path: string): Promise<string>;
  currentTimestamp(): string;
  writeOutput(value: string): void;
  writeError(value: string): void;
}

const defaultDependencies: ReplayDependencies = {
  async readTextFile(path) {
    const fileStats = await stat(path);
    if (!fileStats.isFile() || fileStats.size > MAX_FIXTURE_BYTES) {
      throw new Error('Fixture is not a bounded regular file.');
    }
    return readFile(path, 'utf8');
  },
  currentTimestamp: () => new Date().toISOString(),
  writeOutput: (value) => process.stdout.write(value),
  writeError: (value) => process.stderr.write(value),
};

export async function replayAlert(
  fixturePath: string | undefined,
  dependencies: ReplayDependencies = defaultDependencies,
): Promise<number> {
  if (!fixturePath) {
    dependencies.writeError('Replay failed: provide a local JSON fixture path.\n');
    return 1;
  }
  let text: string;
  try {
    text = await dependencies.readTextFile(resolve(fixturePath));
  } catch {
    dependencies.writeError('Replay failed: could not read a bounded local fixture.\n');
    return 1;
  }
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    dependencies.writeError('Replay failed: fixture is not valid JSON.\n');
    return 1;
  }
  const validated = azureMonitorCommonAlertSchema.safeParse(payload);
  if (!validated.success) {
    dependencies.writeError('Replay failed: alert validation failed.\n');
    return 1;
  }
  try {
    const normalized = normalizeAzureAlert(validated.data, dependencies.currentTimestamp());
    dependencies.writeOutput(`${JSON.stringify(normalized, null, 2)}\n`);
    return 0;
  } catch {
    dependencies.writeError('Replay failed: alert normalization failed.\n');
    return 1;
  }
}

const isMainModule = process.argv[1] !== undefined
  && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMainModule) process.exitCode = await replayAlert(process.argv[2]);
