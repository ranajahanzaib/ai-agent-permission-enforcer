import {
  QueryClient,
  QueryClientProvider,
  useQuery,
} from "@tanstack/react-query";
import {
  Activity,
  ArrowUpRight,
  Check,
  LockKeyhole,
  Play,
  ScrollText,
  ShieldCheck,
  X,
} from "lucide-react";
import React from "react";
import { createRoot } from "react-dom/client";
import { decisionTone } from "./decision";
import "./style.css";

type DemoSession = {
  authenticated: boolean;
  user_id?: string;
  tenant_id?: string;
  display_name?: string;
  role?: string;
  csrf_token?: string;
};
const queryClient = new QueryClient();
const get = async (path: string) => {
  const response = await fetch(path, { credentials: "same-origin" });
  if (!response.ok) throw new Error(`Request failed (${response.status})`);
  return response.json();
};

function App() {
  const summary = useQuery({
    queryKey: ["summary"],
    queryFn: () => get("/api/summary"),
    refetchInterval: 3000,
  });
  const invoices = useQuery({
    queryKey: ["invoices"],
    queryFn: () => get("/api/invoices"),
  });
  const audit = useQuery({
    queryKey: ["audit"],
    queryFn: () => get("/api/audit"),
  });
  const approvals = useQuery({
    queryKey: ["approvals"],
    queryFn: () => get("/api/approvals"),
  });
  const delegations = useQuery({
    queryKey: ["delegations"],
    queryFn: () => get("/api/delegations"),
  });
  const scenarios = useQuery({
    queryKey: ["scenarios"],
    queryFn: () => get("/api/scenarios"),
  });
  const session = useQuery<DemoSession>({
    queryKey: ["session"],
    queryFn: () => get("/api/session"),
  });
  const reports = useQuery({
    queryKey: ["reports"],
    queryFn: () => get("/api/reports"),
    enabled: !!session.data?.authenticated,
  });
  const policies = useQuery({
    queryKey: ["policies"],
    queryFn: () => get("/api/policies"),
  });
  const credentials = useQuery({
    queryKey: ["credentials"],
    queryFn: () => get("/api/agent-credentials"),
    enabled: session.data?.role === "finance_admin",
  });
  const [selectedUser, setSelectedUser] = React.useState("alice");
  const [run, setRun] = React.useState<any>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [issuedToken, setIssuedToken] = React.useState("");

  async function startDemoSession() {
    setError("");
    const response = await fetch("/api/demo/sessions", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_id: selectedUser }),
    });
    const body = await response.json();
    if (!response.ok) {
      setError(
        body.error?.message ?? `Session request failed (${response.status})`,
      );
      return;
    }
    await Promise.all(
      ["session", "summary", "invoices", "approvals", "audit"].map((queryKey) =>
        queryClient.invalidateQueries({ queryKey: [queryKey] }),
      ),
    );
  }

  async function runScenarios() {
    const csrf = session.data?.csrf_token;
    if (!csrf) {
      setError("Start a demo user session before running scenarios.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const response = await fetch("/api/scenarios/run", {
        method: "POST",
        credentials: "same-origin",
        headers: { "x-csrf-token": csrf },
      });
      const report = await response.json();
      setRun(report);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["audit"] }),
        queryClient.invalidateQueries({ queryKey: ["summary"] }),
        queryClient.invalidateQueries({ queryKey: ["reports"] }),
      ]);
    } catch {
      setError(
        "Could not run the simulator. Check that the local API is available.",
      );
    } finally {
      setLoading(false);
    }
  }

  async function approvalAction(
    id: string,
    action: "approve" | "reject" | "submit",
    draftId?: string,
  ) {
    const csrf = session.data?.csrf_token;
    if (!csrf) {
      setError("Start a demo user session before making approval decisions.");
      return;
    }
    setError("");
    const url =
      action === "submit"
        ? `/api/payment-drafts/${draftId}/submit`
        : `/api/approvals/${id}/${action}`;
    const response = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "x-csrf-token": csrf },
    });
    const body = await response.json();
    if (!response.ok) {
      setError(
        body.error?.message ??
          body.error?.code ??
          `Request failed (${response.status})`,
      );
      return;
    }
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["approvals"] }),
      queryClient.invalidateQueries({ queryKey: ["summary"] }),
      queryClient.invalidateQueries({ queryKey: ["audit"] }),
    ]);
  }

  async function revokeDelegation(id: string) {
    const csrf = session.data?.csrf_token;
    if (!csrf) {
      setError("Start a demo user session before revoking a delegation.");
      return;
    }
    const response = await fetch("/api/delegations/" + id + "/revoke", {
      method: "POST",
      credentials: "same-origin",
      headers: { "x-csrf-token": csrf },
    });
    const body = await response.json();
    if (!response.ok) {
      setError(body.error?.message ?? "Could not revoke delegation.");
      return;
    }
    await Promise.all(
      ["delegations", "audit", "summary"].map((queryKey) =>
        queryClient.invalidateQueries({ queryKey: [queryKey] }),
      ),
    );
  }

  async function createDelegation() {
    const csrf = session.data?.csrf_token;
    if (!csrf) {
      setError("Start a demo user session before creating a delegation.");
      return;
    }
    const agentId =
      session.data?.tenant_id === "northstar" ? "northstar-bot" : "finance-bot";
    const response = await fetch("/api/delegations", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "x-csrf-token": csrf },
      body: JSON.stringify({
        agent_id: agentId,
        allowed_actions: ["invoice.read"],
        expires_in_minutes: 30,
      }),
    });
    const body = await response.json();
    if (!response.ok) {
      setError(body.error?.message ?? "Could not create delegation.");
      return;
    }
    await Promise.all(
      ["delegations", "audit", "summary"].map((queryKey) =>
        queryClient.invalidateQueries({ queryKey: [queryKey] }),
      ),
    );
  }

  async function issueCredential() {
    const csrf = session.data?.csrf_token;
    if (!csrf) {
      setError("Start an admin session before issuing an agent credential.");
      return;
    }
    const response = await fetch("/api/agent-credentials", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json", "x-csrf-token": csrf },
      body: JSON.stringify({ agent_id: "finance-bot", expires_in_minutes: 60 }),
    });
    const body = await response.json();
    if (!response.ok) {
      setError(body.error?.message ?? "Could not issue agent credential.");
      return;
    }
    setIssuedToken(body.token);
    await queryClient.invalidateQueries({ queryKey: ["credentials"] });
  }

  async function revokeCredential(id: string) {
    const csrf = session.data?.csrf_token;
    if (!csrf) {
      setError("Start an admin session before revoking credentials.");
      return;
    }
    const response = await fetch(`/api/agent-credentials/${id}/revoke`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "x-csrf-token": csrf },
    });
    const body = await response.json();
    if (!response.ok) {
      setError(body.error?.message ?? "Could not revoke agent credential.");
      return;
    }
    await queryClient.invalidateQueries({ queryKey: ["credentials"] });
  }

  async function endSession() {
    const csrf = session.data?.csrf_token;
    if (!csrf) return;
    await fetch("/api/session/revoke", {
      method: "POST",
      credentials: "same-origin",
      headers: { "x-csrf-token": csrf },
    });
    await Promise.all(
      [
        "session",
        "summary",
        "invoices",
        "approvals",
        "audit",
        "delegations",
      ].map((queryKey) =>
        queryClient.invalidateQueries({ queryKey: [queryKey] }),
      ),
    );
  }

  const isApprover =
    session.data?.authenticated &&
    ["finance_approver", "finance_admin"].includes(session.data.role ?? "");
  const pendingApprovals = (approvals.data ?? []).filter(
    (item: any) => item.status === "PENDING",
  );
  const approvedApprovals = (approvals.data ?? []).filter(
    (item: any) => item.status === "APPROVED",
  );

  return (
    <div className="shell">
      <aside>
        <div className="brand">
          <span className="mark">
            <ShieldCheck size={21} />
          </span>
          <span>
            Agent<span className="blue">Authority</span>
            <small>ENFORCEMENT CONSOLE</small>
          </span>
        </div>
        <nav>
          <a className="active" href="#overview">
            <Activity size={17} /> Overview
          </a>
          <a href="#scenarios">
            <Play size={17} /> Playground
          </a>
          <a href="#approvals">
            <LockKeyhole size={17} /> Approvals{" "}
            <b>{summary.data?.pending_approvals ?? 0}</b>
          </a>
          <a href="#delegations">Delegations</a>
          <a href="#policies">Policy explorer</a>
          <a href="#audit">
            <ScrollText size={17} /> Audit log
          </a>
        </nav>
        <div className="side-bottom">
          <i /> Local demo environment
          <br />
          <span>API connected · Cedar active</span>
        </div>
      </aside>
      <main id="overview">
        <header>
          <div>
            <span className="eyebrow">SECURITY WORKSPACE / OVERVIEW</span>
            <h1>Authorization control plane</h1>
            <p>
              Every agent action is checked against trusted identity,
              delegation, policy, and resource scope.
            </p>
          </div>
          <div className="header-controls">
            <label className="tenant">
              DEMO IDENTITY{" "}
              <select
                aria-label="Demo identity"
                value={selectedUser}
                onChange={(event) => setSelectedUser(event.target.value)}
              >
                <option value="alice">Alice · Operator</option>
                <option value="owen">Owen · Approver</option>
                <option value="olivia">Olivia · Admin</option>
                <option value="bob">Bob · Operator</option>
                <option value="nora">Nora · Approver</option>
              </select>
            </label>
            <button onClick={startDemoSession}>
              {session.data?.authenticated
                ? "Switch identity"
                : "Start demo session"}
            </button>
          </div>
        </header>
        {session.data?.authenticated && (
          <div className="session-note" role="status">
            Signed in as <strong>{session.data.display_name}</strong> ·{" "}
            {session.data.role} · {session.data.tenant_id}
            <button className="inline-action" onClick={endSession}>
              End session
            </button>
          </div>
        )}
        {error && (
          <div className="error-banner" role="alert">
            {error}
          </div>
        )}
        <section className="stats">
          <Metric
            title="Protected resources"
            value={summary.data?.invoice_count ?? "—"}
            note="Seeded invoices"
          />
          <Metric
            title="Audit events"
            value={summary.data?.audit_events ?? "—"}
            note="Persisted decision evidence"
          />
          <Metric
            title="Pending approvals"
            value={summary.data?.pending_approvals ?? "—"}
            note="Human review required"
          />
          <Metric
            title="Policy engine"
            value="CEDAR"
            note="Default deny · v1"
          />
        </section>
        <section className="grid">
          <article className="panel wide" id="scenarios">
            <div className="panel-head">
              <div>
                <span className="eyebrow">DETERMINISTIC SECURITY CHECKS</span>
                <h2>Scenario simulator</h2>
              </div>
              <button onClick={runScenarios} disabled={loading}>
                <Play size={15} />
                {loading ? "Running…" : "Run scenarios"}
              </button>
            </div>
            <p className="muted">
              Exercise implemented adversarial checks through the gateway.
              Unimplemented checks are identified in each saved report.
            </p>
            <div className="scenario-grid">
              {(scenarios.data ?? []).slice(0, 8).map((scenario: any) => (
                <div className="scenario" key={scenario.id}>
                  <span className="id">{scenario.id}</span>
                  <span>{scenario.name}</span>
                  <ArrowUpRight size={14} />
                </div>
              ))}
            </div>
            {run && (
              <div className="run-result">
                <strong>{run.status}</strong>
                <span>
                  {run.reports.filter((item: any) => item.passed).length}{" "}
                  executed checks passed · {run.not_executed?.length ?? 0} not
                  executed
                </span>
                {run.reports.map((item: any) => (
                  <div key={item.scenario_id}>
                    <code>{item.scenario_id}</code>{" "}
                    {item.reason_code ?? item.actual}: {item.actual}
                  </div>
                ))}
              </div>
            )}
            <div className="resource-list report-history">
              <strong>Saved reports</strong>
              {(reports.data ?? []).slice(0, 5).map((report: any) => (
                <div className="resource" key={report.id}>
                  <span>
                    {report.status} ·{" "}
                    {new Date(report.created_at + "Z").toLocaleString()}
                  </span>
                  <a
                    href={`/api/reports/${report.id}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    View JSON
                  </a>
                </div>
              ))}
              {session.data?.authenticated && !reports.data?.length && (
                <div className="table-empty">
                  Run the simulator to save the first report.
                </div>
              )}
            </div>
            <p>
              <a href="/api/openapi.json" target="_blank" rel="noreferrer">
                OpenAPI specification
              </a>
            </p>
          </article>
          <article className="panel" id="approvals">
            <div className="panel-head">
              <div>
                <span className="eyebrow">HUMAN IN THE LOOP</span>
                <h2>Approval queue</h2>
              </div>
              <LockKeyhole size={18} />
            </div>
            {pendingApprovals.length === 0 && approvedApprovals.length === 0 ? (
              <div className="empty">
                <div className="empty-icon">
                  <LockKeyhole size={18} />
                </div>
                <strong>No pending approvals</strong>
                <span>
                  Agent requests requiring a human decision will appear here.
                </span>
              </div>
            ) : (
              <div className="resource-list">
                {[...pendingApprovals, ...approvedApprovals].map(
                  (approval: any) => (
                    <div className="resource approval-row" key={approval.id}>
                      <div>
                        <strong>
                          {approval.invoice_id} · {approval.status}
                        </strong>
                        <span>
                          {approval.tenant_id} · {approval.id.slice(0, 8)}
                        </span>
                        <b>
                          $
                          {(approval.amount_cents / 100).toLocaleString(
                            "en-US",
                            { minimumFractionDigits: 2 },
                          )}
                        </b>
                        <div className="approval-actions">
                          {approval.status === "PENDING" && isApprover && (
                            <>
                              <button
                                onClick={() =>
                                  approvalAction(approval.id, "approve")
                                }
                              >
                                <Check size={13} /> Approve
                              </button>
                              <button
                                className="secondary"
                                onClick={() =>
                                  approvalAction(approval.id, "reject")
                                }
                              >
                                <X size={13} /> Reject
                              </button>
                            </>
                          )}
                          {approval.status === "APPROVED" && isApprover && (
                            <button
                              onClick={() =>
                                approvalAction(
                                  approval.id,
                                  "submit",
                                  approval.draft_id,
                                )
                              }
                            >
                              <Check size={13} /> Submit payment
                            </button>
                          )}
                        </div>
                      </div>
                    </div>
                  ),
                )}
              </div>
            )}
          </article>
          <article className="panel">
            <div className="panel-head">
              <div>
                <span className="eyebrow">REGISTERED TOOL SCOPE</span>
                <h2>Resource inventory</h2>
              </div>
              <span className="count">{invoices.data?.length ?? 0}</span>
            </div>
            <div className="resource-list">
              {(invoices.data ?? []).map((invoice: any) => (
                <div className="resource" key={invoice.id}>
                  <div>
                    <strong>{invoice.id}</strong>
                    <span>
                      {invoice.customer} · {invoice.tenant_id}
                    </span>
                  </div>
                  <b>
                    $
                    {(invoice.amount_cents / 100).toLocaleString("en-US", {
                      minimumFractionDigits: 2,
                    })}
                  </b>
                </div>
              ))}
            </div>
          </article>
          <article className="panel wide" id="delegations">
            <div className="panel-head">
              <div>
                <span className="eyebrow">DELEGATED AUTHORITY</span>
                <h2>Tenant delegations</h2>
              </div>
              <div className="panel-actions">
                <span className="count">
                  {
                    (delegations.data ?? []).filter(
                      (item: any) => item.status === "ACTIVE",
                    ).length
                  }{" "}
                  active
                </span>
                {session.data?.authenticated && (
                  <button onClick={createDelegation}>Grant invoice read</button>
                )}
              </div>
            </div>
            <div className="resource-list">
              {(delegations.data ?? []).map((item: any) => (
                <div className="resource" key={item.id}>
                  <div>
                    <strong>
                      {item.agent_id} · {item.status}
                    </strong>
                    <span>
                      {item.user_id} · expires{" "}
                      {new Date(item.expires_at + "Z").toLocaleString()}
                    </span>
                    <small>{item.allowed_actions.join(" · ")}</small>
                  </div>
                  {item.status === "ACTIVE" &&
                    (item.user_id === session.data?.user_id ||
                      session.data?.role === "finance_admin") && (
                      <button
                        className="secondary"
                        onClick={() => revokeDelegation(item.id)}
                      >
                        Revoke
                      </button>
                    )}
                </div>
              ))}
              {!delegations.data?.length && (
                <div className="table-empty">
                  Sign in to inspect tenant delegations.
                </div>
              )}
            </div>
          </article>
          {session.data?.role === "finance_admin" && (
            <article className="panel wide">
              <div className="panel-head">
                <div>
                  <span className="eyebrow">SERVER-SIDE AGENT AUTH</span>
                  <h2>Agent credentials</h2>
                </div>
                <button onClick={issueCredential}>
                  Issue 60 minute credential
                </button>
              </div>
              <p className="muted">
                Credential secrets are shown once. Store them in trusted server
                configuration; never in browser storage.
              </p>
              {issuedToken && (
                <div className="credential-secret">
                  <code>{issuedToken}</code>
                  <button
                    className="secondary"
                    onClick={() => setIssuedToken("")}
                  >
                    Clear
                  </button>
                </div>
              )}
              <div className="resource-list">
                {(credentials.data ?? []).map((item: any) => (
                  <div className="resource" key={item.id}>
                    <div>
                      <strong>{item.agent_id}</strong>
                      <span>
                        {item.id.slice(0, 8)} · expires{" "}
                        {new Date(item.expires_at + "Z").toLocaleString()}
                      </span>
                    </div>
                    {!item.revoked && (
                      <button
                        className="secondary"
                        onClick={() => revokeCredential(item.id)}
                      >
                        Revoke
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </article>
          )}
          <article className="panel wide" id="audit">
            <div className="panel-head">
              <div>
                <span className="eyebrow">EVIDENCE STREAM</span>
                <h2>Recent authorization events</h2>
              </div>
              <span className="live">● LIVE</span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>DECISION</th>
                    <th>TOOL</th>
                    <th>ACTING AGENT</th>
                    <th>DELEGATING USER</th>
                    <th>TIME</th>
                  </tr>
                </thead>
                <tbody>
                  {(audit.data ?? []).slice(0, 6).map((event: any) => (
                    <tr key={event.id}>
                      <td>
                        <span className={decisionTone(event.result)}>
                          {event.result.split(":")[0]}
                        </span>
                      </td>
                      <td>
                        <code>{event.tool}</code>
                      </td>
                      <td>{event.agent_id}</td>
                      <td>{event.user_id}</td>
                      <td>{new Date(event.at + "Z").toLocaleTimeString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!audit.data?.length && (
                <div className="table-empty">
                  No events yet. Run a security scenario to create audit
                  evidence.
                </div>
              )}
            </div>
          </article>
          <article className="panel wide" id="policies">
            <div className="panel-head">
              <div>
                <span className="eyebrow">POLICY EXPLORER</span>
                <h2>{policies.data?.engine ?? "Cedar"} authorization rules</h2>
              </div>
              <span className="count">{policies.data?.version ?? "…"}</span>
            </div>
            <p className="muted">
              Policies and schema are served by the backend. Finance admins can
              update the active policy through the API; runtime replacement
              applies to agent invocations and payment submission.
            </p>
            <details>
              <summary>View Cedar policy source</summary>
              <pre className="policy-source">
                {policies.data?.policy ?? "Loading policy…"}
              </pre>
            </details>
            <details>
              <summary>View Cedar schema</summary>
              <pre className="policy-source">
                {policies.data?.schema ?? "Loading schema…"}
              </pre>
            </details>
          </article>
        </section>
        <footer>
          <span>
            AI Agent Permission Enforcer <i>·</i> Application-side authorization
            for AI agent tools
          </span>
          <span>DEMO MODE · NOT PRODUCTION AUTHENTICATION</span>
        </footer>
      </main>
    </div>
  );
}

function Metric({
  title,
  value,
  note,
}: {
  title: string;
  value: unknown;
  note: string;
}) {
  return (
    <div className="metric">
      <span>{title}</span>
      <strong>{value as React.ReactNode}</strong>
      <small>{note}</small>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>,
);
