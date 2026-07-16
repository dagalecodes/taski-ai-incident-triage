import { tool, type Tool } from '@openai/agents';
import { z } from 'zod';
import type { TriageResult } from '../contracts/triageResult.js';
import {
  containsSensitivePattern,
  redactUntrustedText,
  safeEvidenceReference,
  type EvidenceLedgerEntry,
  type SafeIncidentContext,
} from '../security/triageGuardrails.js';

export const DIAGNOSTIC_TOOL_NAMES = [
  'get_service_health',
  'get_recent_error_summary',
  'get_resource_metrics',
  'get_latest_deployment',
  'get_matching_runbook',
] as const;
export type DiagnosticToolName = typeof DIAGNOSTIC_TOOL_NAMES[number];
type EvidenceSource = TriageResult['evidence'][number]['source'];

const emptyInputSchema = z.object({}).strict();
const providerEvidenceSchema = z.object({
  finding: z.string().min(1).max(1_500),
  reference: z.string().min(1).max(512).optional(),
}).strict();
const providerResultSchema = z.object({
  available: z.boolean(),
  evidence: z.array(providerEvidenceSchema).max(2),
  limitation: z.string().min(1).max(500).optional(),
}).strict().superRefine((value, context) => {
  if (!value.available && value.evidence.length > 0) {
    context.addIssue({ code: 'custom', message: 'Unavailable diagnostics cannot contain evidence.' });
  }
});

export type DiagnosticProviderResult = z.infer<typeof providerResultSchema>;
export interface DiagnosticProvider {
  getServiceHealth(context: SafeIncidentContext): Promise<unknown>;
  getRecentErrorSummary(context: SafeIncidentContext): Promise<unknown>;
  getResourceMetrics(context: SafeIncidentContext): Promise<unknown>;
  getLatestDeployment(context: SafeIncidentContext): Promise<unknown>;
  getMatchingRunbook(context: SafeIncidentContext): Promise<unknown>;
}

const SOURCE_BY_TOOL: Readonly<Record<DiagnosticToolName, EvidenceSource>> = {
  get_service_health: 'service_health',
  get_recent_error_summary: 'recent_errors',
  get_resource_metrics: 'resource_metrics',
  get_latest_deployment: 'latest_deployment',
  get_matching_runbook: 'runbook',
};

const METHOD_BY_TOOL: Readonly<Record<DiagnosticToolName, keyof DiagnosticProvider>> = {
  get_service_health: 'getServiceHealth',
  get_recent_error_summary: 'getRecentErrorSummary',
  get_resource_metrics: 'getResourceMetrics',
  get_latest_deployment: 'getLatestDeployment',
  get_matching_runbook: 'getMatchingRunbook',
};

function unavailableResult(): DiagnosticProviderResult {
  return { available: false, evidence: [], limitation: 'Diagnostic data is unavailable.' };
}

function sanitizeProviderResult(value: unknown): DiagnosticProviderResult {
  const parsed = providerResultSchema.safeParse(value);
  if (!parsed.success) return unavailableResult();
  const evidence = parsed.data.evidence.map(item => {
    const finding = redactUntrustedText(item.finding, 1_500);
    const reference = item.reference === undefined ? undefined : redactUntrustedText(item.reference, 512);
    if (!finding || containsSensitivePattern(finding) || !safeEvidenceReference(reference)) {
      return null;
    }
    return reference === undefined ? { finding } : { finding, reference };
  }).filter((item): item is { finding: string; reference?: string } => item !== null);
  const limitation = parsed.data.limitation
    ? redactUntrustedText(parsed.data.limitation, 500)
    : (evidence.length ? undefined : 'Diagnostic data is unavailable.');
  return {
    available: parsed.data.available && evidence.length > 0,
    evidence: parsed.data.available ? evidence : [],
    ...(limitation ? { limitation } : {}),
  };
}

export class DiagnosticToolkit {
  readonly #ledger: EvidenceLedgerEntry[] = [];
  readonly #results = new Map<DiagnosticToolName, DiagnosticProviderResult>();

  constructor(
    private readonly incidentContext: SafeIncidentContext,
    private readonly provider: DiagnosticProvider,
  ) {}

  async execute(name: DiagnosticToolName, input: unknown): Promise<DiagnosticProviderResult> {
    if (!emptyInputSchema.safeParse(input).success) throw new Error('Invalid diagnostic tool input.');
    const cached = this.#results.get(name);
    if (cached) return structuredClone(cached);
    let raw: unknown;
    try {
      raw = await this.provider[METHOD_BY_TOOL[name]](this.incidentContext);
    } catch {
      return unavailableResult();
    }
    const result = sanitizeProviderResult(raw);
    this.#results.set(name, result);
    const source = SOURCE_BY_TOOL[name];
    for (const evidence of result.evidence) {
      if (this.#ledger.length >= 10) break;
      this.#ledger.push(evidence.reference === undefined
        ? { source, finding: evidence.finding }
        : { source, finding: evidence.finding, reference: evidence.reference });
    }
    return structuredClone(result);
  }

  evidenceLedger(): readonly EvidenceLedgerEntry[] {
    return this.#ledger.map(entry => ({ ...entry }));
  }
}

export function createDiagnosticTools(toolkit: DiagnosticToolkit): Tool[] {
  return DIAGNOSTIC_TOOL_NAMES.map(name => tool({
    name,
    description: `Read-only diagnostic lookup for ${SOURCE_BY_TOOL[name]} scoped to the current incident.`,
    parameters: emptyInputSchema,
    strict: true,
    timeoutMs: 2_000,
    timeoutBehavior: 'error_as_result',
    timeoutErrorFunction: () => JSON.stringify(unavailableResult()),
    errorFunction: () => JSON.stringify(unavailableResult()),
    execute: async input => toolkit.execute(name, input),
  }));
}

export function createUnavailableDiagnosticProvider(): DiagnosticProvider {
  const unavailable = async (): Promise<DiagnosticProviderResult> => unavailableResult();
  return {
    getServiceHealth: unavailable,
    getRecentErrorSummary: unavailable,
    getResourceMetrics: unavailable,
    getLatestDeployment: unavailable,
    getMatchingRunbook: unavailable,
  };
}
