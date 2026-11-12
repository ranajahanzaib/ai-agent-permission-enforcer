CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  display_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('finance_operator','finance_approver','finance_admin')),
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','REVOKED'))
);
CREATE TABLE IF NOT EXISTS agents(
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','REVOKED'))
);
CREATE TABLE IF NOT EXISTS delegations(
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  agent_id TEXT NOT NULL REFERENCES agents(id),
  allowed_actions TEXT NOT NULL,
  resource_tenant_id TEXT NOT NULL,
  issued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','REVOKED'))
);
CREATE TABLE IF NOT EXISTS sessions(
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  csrf_token TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS agent_credentials(
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  agent_id TEXT NOT NULL REFERENCES agents(id),
  token_hash TEXT NOT NULL UNIQUE,
  created_by_user_id TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_agent_credentials_agent ON agent_credentials(agent_id,expires_at,revoked_at);
CREATE TABLE IF NOT EXISTS payment_drafts(
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  invoice_id TEXT NOT NULL REFERENCES invoices(id),
  amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
  currency TEXT NOT NULL DEFAULT 'USD',
  recipient TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('DRAFT','PENDING_APPROVAL','REJECTED','APPROVED','SUBMITTED','FAILED')),
  version INTEGER NOT NULL DEFAULT 1,
  created_by_agent_id TEXT NOT NULL REFERENCES agents(id),
  delegated_user_id TEXT NOT NULL REFERENCES users(id),
  idempotency_key TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(tenant_id,idempotency_key)
);
CREATE TABLE IF NOT EXISTS approval_requests(
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  payment_draft_id TEXT NOT NULL REFERENCES payment_drafts(id),
  requested_by_agent_id TEXT NOT NULL REFERENCES agents(id),
  delegation_id TEXT NOT NULL REFERENCES delegations(id),
  delegated_user_id TEXT NOT NULL REFERENCES users(id),
  approver_user_id TEXT REFERENCES users(id),
  requested_action TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
  currency TEXT NOT NULL,
  recipient TEXT NOT NULL,
  resource_version INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT NOT NULL,
  decided_at TEXT,
  consumed_at TEXT,
  status TEXT NOT NULL CHECK(status IN ('PENDING','APPROVED','REJECTED','EXPIRED','CONSUMED'))
);
CREATE TABLE IF NOT EXISTS payment_executions(
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  payment_draft_id TEXT NOT NULL UNIQUE REFERENCES payment_drafts(id),
  approval_id TEXT NOT NULL UNIQUE REFERENCES approval_requests(id),
  executed_by_user_id TEXT NOT NULL REFERENCES users(id),
  amount_cents INTEGER NOT NULL,
  currency TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_delegations_agent ON delegations(agent_id,status,expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_payment_drafts_tenant_status ON payment_drafts(tenant_id,status);
CREATE INDEX IF NOT EXISTS idx_approval_tenant_status ON approval_requests(tenant_id,status,expires_at);
CREATE INDEX IF NOT EXISTS idx_payments_tenant ON payment_executions(tenant_id);
CREATE TABLE IF NOT EXISTS invocation_evidence(
  invocation_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  delegation_id TEXT,
  delegated_user_id TEXT NOT NULL,
  credential_reference TEXT NOT NULL,
  tool_id TEXT NOT NULL,
  disposition TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  resource_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS simulation_reports(
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  run_by_user_id TEXT NOT NULL REFERENCES users(id),
  status TEXT NOT NULL,
  report_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_simulation_reports_tenant ON simulation_reports(tenant_id,created_at DESC);
CREATE TABLE IF NOT EXISTS policy_versions(
  version INTEGER PRIMARY KEY,
  cedar_source TEXT NOT NULL,
  created_by_user_id TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE','SUPERSEDED'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_one_active ON policy_versions(status) WHERE status='ACTIVE';
