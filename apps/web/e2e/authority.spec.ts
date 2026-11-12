import { expect, test } from "@playwright/test";

const api = "http://127.0.0.1:8787";
const agentToken =
  process.env.AA_DEMO_AGENT_TOKEN ?? "playwright-fixture-token";

test("dashboard scopes data, runs scenarios, and keeps reports", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Start demo session" }).click();
  await expect(page.getByText("INV-1042", { exact: true })).toBeVisible();
  await expect(page.getByText("INV-2042", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Run scenarios" }).click();
  await expect(page.getByText("PASS", { exact: true })).toBeVisible();
  await expect(page.getByText(/not executed/)).toBeVisible();
  await expect(
    page.getByRole("link", { name: "View JSON" }).first(),
  ).toBeVisible();
});

test("agent draft requires a separate human approval and one payment submission", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Start demo session" }).click();

  const key = `e2e-${crypto.randomUUID()}`;
  const draftResponse = await page.request.post(`${api}/api/invoke`, {
    headers: { authorization: `Bearer ${agentToken}` },
    data: {
      tool: "create_payment_draft",
      invoice_id: "INV-1043",
      amount_cents: 1000,
      idempotency_key: key,
    },
  });
  expect(draftResponse.status()).toBe(201);
  const draft = await draftResponse.json();
  const approvalResponse = await page.request.post(`${api}/api/invoke`, {
    headers: { authorization: `Bearer ${agentToken}` },
    data: { tool: "request_payment_approval", draft_id: draft.result.draft_id },
  });
  expect(approvalResponse.status()).toBe(202);
  const approval = await approvalResponse.json();

  await page.getByLabel("Demo identity").selectOption("owen");
  await page.getByRole("button", { name: "Switch identity" }).click();
  await expect(page.getByText("INV-1043 · PENDING")).toBeVisible();
  await page.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByText("INV-1043 · APPROVED")).toBeVisible();
  const approvalRow = page
    .locator(".approval-row")
    .filter({ hasText: approval.result.approval_id.slice(0, 8) });
  await approvalRow.getByRole("button", { name: "Submit payment" }).click();
  await expect(approvalRow).toHaveCount(0);

  const session = await page.evaluate(async () =>
    (await fetch("/api/session")).json(),
  );
  const consumedStatus = await page.evaluate(async (approvalId) => {
    const approvals = await (await fetch("/api/approvals")).json();
    return approvals.find((item: { id: string }) => item.id === approvalId)
      ?.status;
  }, approval.result.approval_id);
  expect(consumedStatus).toBe("CONSUMED");
  const replay = await page.request.post(
    `${api}/api/payment-drafts/${draft.result.draft_id}/submit`,
    {
      headers: { "x-csrf-token": session.csrf_token },
    },
  );
  expect(replay.status()).toBe(409);
});
