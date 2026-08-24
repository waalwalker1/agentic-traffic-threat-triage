import { test, expect } from '@playwright/test';

test.describe('SOC Analyst End-to-End Workflow', () => {
  test('complete triage, inspection, disposition, and evaluation workflow', async ({ page }) => {
    // 1. Open analyst dashboard
    await page.goto('/');
    await expect(page).toHaveTitle(/Agentic Traffic Threat Triage/i);

    // 2. Verify Overview page loaded
    await expect(page.getByText(/Defensive Traffic-Intelligence/i)).toBeVisible();
    await expect(page.getByText(/Architecture Invariants/i)).toBeVisible();

    // 3. Navigate to Session Explorer
    await page.getByRole('button', { name: /Session Explorer/i }).click();
    await expect(page.getByText(/Sessions/i)).toBeVisible();

    // 4. Select a session if present
    const firstSession = page.locator('.font-mono.font-semibold.text-sky-400').first();
    if (await firstSession.isVisible()) {
      await firstSession.click();
      await expect(page.getByText(/Deterministic Evidence Items/i)).toBeVisible();

      // Trigger Triage
      const triageBtn = page.getByRole('button', { name: /Run 6-Agent Triage/i });
      if (await triageBtn.isVisible()) {
        await triageBtn.click();
        // Wait for Incident Triage tab to activate
        await expect(page.getByText(/Incident Brief/i)).toBeVisible();
        await expect(page.getByText(/Grounded Findings & Citations/i)).toBeVisible();

        // Submit Human Disposition
        const notesArea = page.getByPlaceholder(/Enter SOC analyst forensic notes/i);
        await notesArea.fill('Verified automated scrapers via e2e test.');
        await page.getByRole('button', { name: /Confirmed Abuse/i }).click();

        // Check disposition recorded
        await expect(page.getByText(/CONFIRMED_ABUSE/i)).toBeVisible();
      }
    }

    // 5. Navigate to Benchmark Evals tab
    await page.getByRole('button', { name: /Benchmark Evals/i }).click();
    await expect(page.getByText(/Reproducible Benchmark Evaluations/i)).toBeVisible();
  });
});
