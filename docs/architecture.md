# Architecture

The Rust API is the trusted boundary. It accepts a registered tool identifier, resolves a hashed credential record to its registered agent and tenant, validates delegation state and resource ownership, asks Cedar for a policy decision, writes invocation evidence, and only then reaches a fixed handler. The React application is a viewer and simulator; browser visibility is not an authorization mechanism.

```mermaid
flowchart LR
  A[Agent request] --> G[Axum gateway]
  G --> I[Credential and delegation lookup]
  I --> T[Tenant and resource check]
  T --> C[Cedar policy evaluation]
  C -->|deny/error| D[Persist denial]
  C -->|allow| H[Registered handler]
  H --> DB[(SQLite)]
  H --> AU[Persist audit evidence]
  U[Human approver] --> AP[Approval workflow]
  AP --> C
```

Current app is an executable reference slice, not a production-ready authentication service. See [security limitations](security-limitations.md).
