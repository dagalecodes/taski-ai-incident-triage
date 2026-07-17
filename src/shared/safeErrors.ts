export type FailureCategory = 'configuration' | 'invalid_message' | 'network' | 'remote' | 'timeout' | 'unexpected';

export class SafePipelineError extends Error {
  constructor(public readonly category: FailureCategory, message: string) {
    super(message);
    this.name = 'SafePipelineError';
  }
}

export function safeError(category: FailureCategory): SafePipelineError {
  return new SafePipelineError(category, `Incident processing failed: ${category}.`);
}
