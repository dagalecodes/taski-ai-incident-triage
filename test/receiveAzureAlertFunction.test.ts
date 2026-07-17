import { HttpRequest, type InvocationContext } from '@azure/functions';
import { readFile } from 'node:fs/promises';
import { describe, expect, it, vi } from 'vitest';
import { receiveAzureAlertHandler } from '../src/functions/receiveAzureAlert.js';

describe('Azure alert handler safe validation diagnostics', () => {
  it('logs only fixed validation categories for a generic HTTP 400', async () => {
    const payload = JSON.parse(await readFile(
      new URL('./fixtures/azure-alert-standard-availability-fired.json', import.meta.url),
      'utf8',
    )) as { data: { essentials: Record<string, unknown>; customProperties: unknown } };
    payload.data.essentials.alertId = '';
    payload.data.essentials.alertRule = 'submitted-rule-must-not-be-logged';
    payload.data.customProperties = { secret: 'submitted-secret-must-not-be-logged' };
    const warn = vi.fn();
    const context = {
      warn,
      info: vi.fn(),
      error: vi.fn(),
      extraOutputs: { set: vi.fn() },
    } as unknown as InvocationContext;
    const request = new HttpRequest({
      method: 'POST',
      url: 'https://submitted-url-must-not-be-logged.invalid/api/alerts/azure-monitor',
      headers: { 'content-type': 'application/json' },
      body: { string: JSON.stringify(payload) },
    });

    await expect(receiveAzureAlertHandler(request, context)).resolves.toEqual({
      status: 400, jsonBody: { error: 'Alert validation failed.' },
    });
    expect(warn).toHaveBeenCalledWith('Azure alert rejected.', {
      category: 'http_400', validationCategories: ['data.essentials'],
    });
    const logged = JSON.stringify(warn.mock.calls);
    for (const forbidden of [
      'submitted-rule-must-not-be-logged',
      'submitted-secret-must-not-be-logged',
      'submitted-url-must-not-be-logged',
    ]) expect(logged).not.toContain(forbidden);
    expect(context.extraOutputs.set).not.toHaveBeenCalled();
  });
});
