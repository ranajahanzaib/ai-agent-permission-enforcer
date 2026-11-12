# Calling the authorization gateway from an agent runtime

The sample TypeScript adapter lives in [`packages/ai-agent-permission-enforcer-client`](../packages/ai-agent-permission-enforcer-client). Run it in the trusted server process that hosts your agent. Keep the bearer credential in server configuration; never send it to a browser or let the model choose it.

```ts
import { AI Agent Permission EnforcerClient } from '@ai-agent-permission-enforcer/client';

const authority = new AI Agent Permission EnforcerClient({
  baseUrl: process.env.AGENT_AUTHORITY_URL!,
  bearerToken: process.env.AGENT_AUTHORITY_TOKEN!,
});

const outcome = await authority.invoke({
  tool: 'read_invoice',
  invoice_id: 'INV-1042',
});

if (outcome.decision?.disposition !== 'ALLOW') {
  // Treat denial as a final authorization decision. Do not call the business API directly.
  return { status: 'denied', reason: outcome.decision?.reason_code };
}

return outcome.result;
```

The adapter sends a typed request to `/api/invoke`; the Rust gateway resolves identity and delegation, checks tenant ownership and Cedar policy, records evidence, then reaches a registered handler. A 403 authorization response is returned as a structured denial. Network, server, and malformed-response failures throw so callers can fail closed.

For an MCP server, put this same call inside each protected tool handler. The MCP transport authenticates its own caller, while the application backend remains responsible for resolving the delegated user, checking the resource and current policy, and enforcing approval requirements. This repository does not claim MCP transport or OAuth protocol conformance.
