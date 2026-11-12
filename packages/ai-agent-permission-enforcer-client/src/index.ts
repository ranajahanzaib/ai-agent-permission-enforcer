/** Server-side client for the AI Agent Permission Enforcer invocation gateway. Never ship the bearer token to a browser. */
export type ToolInvocation = {
  tool: string;
  invoice_id?: string;
  amount_cents?: number;
  draft_id?: string;
  idempotency_key?: string;
  untrusted_text?: string;
};

export type InvocationResponse<T = unknown> = {
  request_id?: string;
  decision?: { disposition: string; reason_code: string; policy_references?: string[] };
  result?: T;
  disposition?: string;
  reason_code?: string;
};

export type AI Agent Permission EnforcerClientOptions = {
  baseUrl: string;
  bearerToken: string;
  fetchImpl?: typeof fetch;
};

export class AI Agent Permission EnforcerClient {
  private readonly baseUrl: string;
  private readonly bearerToken: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: AI Agent Permission EnforcerClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.bearerToken = options.bearerToken;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async invoke<T = unknown>(invocation: ToolInvocation): Promise<InvocationResponse<T>> {
    const response = await this.fetchImpl(`${this.baseUrl}/api/invoke`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${this.bearerToken}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(invocation),
    });
    const body = await response.json() as InvocationResponse<T>;
    if (!response.ok && response.status !== 403) {
      throw new Error(`AI Agent Permission Enforcer request failed (${response.status}): ${body.reason_code ?? body.decision?.reason_code ?? 'REQUEST_FAILED'}`);
    }
    return body;
  }
}
