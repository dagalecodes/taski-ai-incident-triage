import { readFile } from 'node:fs/promises';
import { describe, expect, it, vi } from 'vitest';
import { replayAlert, type ReplayDependencies } from '../scripts/replayAlert.js';

function dependenciesFor(name: string, output: string[], errors: string[]): ReplayDependencies {
  return {
    readTextFile: () => readFile(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'),
    currentTimestamp: () => '2026-07-16T10:00:00Z',
    writeOutput: (value) => output.push(value),
    writeError: (value) => errors.push(value),
  };
}

describe('local alert replay', () => {
  it('returns success and emits only normalized JSON without network access', async () => {
    const output: string[] = [];
    const errors: string[] = [];
    const network = vi.fn(() => { throw new Error('Network access is forbidden.'); });
    vi.stubGlobal('fetch', network);
    const code = await replayAlert('synthetic.json', dependenciesFor('azure-alert-fired.json', output, errors));
    expect(code).toBe(0);
    expect(errors).toEqual([]);
    expect(output).toHaveLength(1);
    expect(() => JSON.parse(output[0] ?? '')).not.toThrow();
    expect(network).not.toHaveBeenCalled();
  });

  it('returns nonzero with a concise error for invalid input', async () => {
    const output: string[] = [];
    const errors: string[] = [];
    expect(await replayAlert('invalid.json', dependenciesFor('azure-alert-invalid.json', output, errors))).toBe(1);
    expect(output).toEqual([]);
    expect(errors.join('')).toBe('Replay failed: alert validation failed.\n');
  });

  it('does not emit malicious ignored content', async () => {
    const output: string[] = [];
    const errors: string[] = [];
    expect(await replayAlert('malicious.json', dependenciesFor('azure-alert-malicious.json', output, errors))).toBe(0);
    expect(output.join('')).not.toContain('FAKE_DEMO');
    expect(output.join('')).not.toContain('Ignore all safeguards');
  });
});
