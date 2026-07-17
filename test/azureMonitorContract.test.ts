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

  it('accepts Standard availability payloads and normalizes optional empty and null fields', async () => {
    for (const name of [
      'azure-alert-standard-availability-fired.json',
      'azure-alert-standard-availability-resolved.json',
    ]) {
      const parsed = azureMonitorCommonAlertSchema.parse(await fixture(name));
      expect(parsed.data.essentials.description).toBeUndefined();
      expect(parsed.data.alertContext).toMatchObject({
        conditionType: 'WebtestLocationAvailabilityCriteria', properties: null,
      });
      expect(parsed.data.customProperties).toBeUndefined();
    }

    const whitespaceDescription = structuredClone(await validFired());
    whitespaceDescription.data.essentials.description = '   ';
    expect(azureMonitorCommonAlertSchema.parse(whitespaceDescription).data.essentials.description).toBeUndefined();

    const boundedDescription = structuredClone(await validFired());
    boundedDescription.data.essentials.description = `  ${'x'.repeat(1_000)} \n`;
    expect(azureMonitorCommonAlertSchema.parse(boundedDescription).data.essentials.description)
      .toBe('x'.repeat(1_000));

    const oversizedDescription = structuredClone(await validFired());
    oversizedDescription.data.essentials.description = `  ${'x'.repeat(1_001)} \n`;
    expect(azureMonitorCommonAlertSchema.safeParse(oversizedDescription).success).toBe(false);

    const absentAndNull = structuredClone(await fixture('azure-alert-fired.json')) as {
      data: {
        essentials: { description?: string };
        alertContext: unknown;
        customProperties?: unknown;
      };
    };
    delete absentAndNull.data.essentials.description;
    absentAndNull.data.alertContext = null;
    delete absentAndNull.data.customProperties;
    const normalized = azureMonitorCommonAlertSchema.parse(absentAndNull);
    expect(normalized.data.essentials.description).toBeUndefined();
    expect(normalized.data.alertContext).toBeUndefined();
    expect(normalized.data.customProperties).toBeUndefined();
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

  it('retains provider object and complete payload size limits', async () => {
    const oversizedContext = structuredClone(await validFired());
    oversizedContext.data.alertContext = { content: 'x'.repeat((32 * 1024) + 1) };
    expect(azureMonitorCommonAlertSchema.safeParse(oversizedContext).success).toBe(false);

    const oversizedPayload = structuredClone(await validFired()) as Record<string, unknown>;
    oversizedPayload.padding = 'x'.repeat((256 * 1024) + 1);
    expect(azureMonitorCommonAlertSchema.safeParse(oversizedPayload).success).toBe(false);
  });
});
