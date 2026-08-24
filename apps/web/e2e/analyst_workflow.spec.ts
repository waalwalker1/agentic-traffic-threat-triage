import { test, expect } from '@playwright/test';

test.describe('SOC Analyst End-to-End Workflow', () => {
  test('complete triage, inspection, disposition, and evaluation workflow', async ({ page, request }) => {
    // 0. Seed deterministic session data via API
    const seedEvent = {
      event_id: 'evt_e2e_001',
      schema_version: '1.0.0',
      timestamp: '2026-01-15T08:00:00Z',
      session_id: 'sess_e2e_analyst_01',
      source_id_hash: 'src_e2e_001',
      request_method: 'GET',
      route_template: '/api/v1/products',
      status_code: 200,
      response_bytes: 1024,
      latency_ms: 45.0,
      user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PlaywrightTest/1.0',
      accept_language: 'en-US',
      header_names: ['host', 'user-agent', 'accept'],
      content_type: 'application/json',
      has_auth_context: false,
      identity_claim: 'ai_agent:test_runner',
      identity_proof_type: 'signature',
      identity_proof_value: 'invalid_sig_payload',
      identity_proof_valid: false,
      actor_hint: 'ai_agent',
      mcp_method: null,
      mcp_tool_category: null,
      synthetic_scenario_id: 'claimed_ai_no_proof',
      synthetic_ground_truth: 'threat',
    };

    const ingestRes = await request.post('http://localhost:8000/api/v1/ingest', {
      data: { events: [seedEvent] },
    });
    expect(ingestRes.ok()).toBeTruthy();

    // 1. Open analyst dashboard
    await page.goto('/');
    await expect(page).toHaveTitle(/Agentic Traffic Threat Triage/i);

    // 2. Verify Overview page loaded
    await expect(page.getByText(/Defensive Traffic-Intelligence/i)).toBeVisible();
    await expect(page.getByText(/Architecture Invariants/i)).toBeVisible();

    // 3. Navigate to Session Explorer
    await page.getByRole('button', { name: /Session Explorer/i }).click();
    await expect(page.getByText(/Sessions/i)).toBeVisible();

    // 4. Select the seeded session
    const targetSession = page.getByText('sess_e2e_analyst_01').first();
    await expect(targetSession).toBeVisible();
    await targetSession.click();

    // Verify evidence items loaded
    await expect(page.getByText(/Deterministic Evidence Items/i)).toBeVisible();

    // 5. Trigger 6-Agent Triage
    const triageBtn = page.getByRole('button', { name: /Run 6-Agent Triage/i });
    await expect(triageBtn).toBeVisible();
    await triageBtn.click();

    // Wait for Incident Brief and Grounded Findings
    await expect(page.getByText(/Incident Brief/i)).toBeVisible();
    await expect(page.getByText(/Grounded Findings & Citations/i)).toBeVisible();

    // 6. Submit Human Disposition
    const notesArea = page.getByPlaceholder(/Enter SOC analyst forensic notes/i);
    await expect(notesArea).toBeVisible();
    await notesArea.fill('Verified automated scraping with invalid signature via E2E test.');
    await page.getByRole('button', { name: /Confirmed Abuse/i }).click();

    // 7. Verify disposition badge recorded
    await expect(page.getByText(/CONFIRMED_ABUSE/i)).toBeVisible();

    // 8. Refresh page to verify persistence
    await page.reload();
    await page.getByRole('button', { name: /Session Explorer/i }).click();
    await targetSession.click();
    await expect(page.getByText(/CONFIRMED_ABUSE/i)).toBeVisible();

    // 9. Navigate to Benchmark Evals tab
    await page.getByRole('button', { name: /Benchmark Evals/i }).click();
    await expect(page.getByText(/Reproducible Benchmark Evaluations/i)).toBeVisible();
  });
});
