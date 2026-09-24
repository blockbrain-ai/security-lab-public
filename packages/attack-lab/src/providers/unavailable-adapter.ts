import type { InvokeOptions, ModelAdapter, ModelResponse } from './contracts.js';

/**
 * UnavailableAdapter — explicit placeholder for roles whose provider
 * credentials are unavailable in the current environment.
 *
 * This is only intended for resume/verification flows where the caller
 * can fall back to deterministic behavior. Any direct invocation throws.
 */
export class UnavailableAdapter implements ModelAdapter {
  readonly provider = 'unavailable';
  readonly model: string;
  readonly supportsNativeSessionResume = false;

  constructor(
    model: string,
    readonly reason: string,
  ) {
    this.model = model;
  }

  async invoke<T = unknown>(_options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    throw new Error(this.reason);
  }
}

export function isUnavailableAdapter(adapter: ModelAdapter | undefined | null): adapter is UnavailableAdapter {
  return Boolean(adapter && adapter.provider === 'unavailable');
}
