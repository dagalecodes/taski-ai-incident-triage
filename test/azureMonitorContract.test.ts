import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { azureMonitorCommonAlertSchema } from '../src/contracts/azureMonitor.js';

async function fixture(name: string): Promise<unknown> {
  return JSON.parse(await readFile(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
}

async function validFired() {
  return azureMonitorCommonAlertSchema.parse(await fixture('azure-alert-fired.json'));
}

describe('Azure Monitor Common Alert Schema contract', () => {
  it('accepts the fired and resolved fixtures', async () => {
    expect(azureMonitorCommonAlertSchema.safeParse(await fixture('azure-alert-fired.json')).success).toBe(true);
    expect(azureMonitorCommonAlertSchema.safeParse(await fixture('azure-alert-resolved.json')).success).toBe(true);
  });

  it('rejects the invalid fixture', async () => {
    expect(azureMonitorCommonAlertSchema.safeParse(await fixture('azure-alert-invalid.json')).success).toBe(false);
  });

  it('rejects missing targets, invalid timestamps, conditions, severities, and oversized text', async () => {
    const missingTarget = structuredClone(await validFired());
    missingTarget.data.essentials.alertTargetIDs = [];
    expect(azureMonitorCommonAlertSchema.safeParse(missingTarget).success).toBe(false);

    const invalidTimestamp = structuredClone(await validFired());
    invalidTimestamp.data.essentials.firedDateTime = '2026-02-30T08:00:00Z';
    expect(azureMonitorCommonAlertSchema.safeParse(invalidTimestamp).success).toBe(false);

    const unsupportedCondition = structuredClone(await validFired());
    unsupportedCondition.data.essentials.monitorCondition = 'resolved';
    expect(azureMonitorCommonAlertSchema.safeParse(unsupportedCondition).success).toBe(false);

    const unsupportedSeverity = { ...structuredClone(await validFired()), data: {
      ...(await validFired()).data,
      essentials: { ...(await validFired()).data.essentials, severity: 'Sev9' },
    } };
    expect(azureMonitorCommonAlertSchema.safeParse(unsupportedSeverity).success).toBe(false);

    const oversized = structuredClone(await validFired());
    oversized.data.essentials.alertRule = 'x'.repeat(513);
    expect(azureMonitorCommonAlertSchema.safeParse(oversized).success).toBe(false);
  });

  it('normalizes monitorCondition case-insensitively', async () => {
    const parsed = azureMonitorCommonAlertSchema.parse(await fixture('azure-alert-malicious.json'));
    expect(parsed.data.essentials.monitorCondition).toBe('fired');
  });
});
