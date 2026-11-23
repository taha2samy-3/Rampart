import { expect, test } from './fixtures';
import path from 'node:path';
import fs from 'node:fs';

const ARTIFACT_DIR = process.env.ARTIFACT_DIR || path.join(process.cwd(), 'playwright-screenshots');
try {
  if (!fs.existsSync(ARTIFACT_DIR)) {
    fs.mkdirSync(ARTIFACT_DIR, { recursive: true });
  }
} catch {
  // directory creation fallback
}

test('capture screenshots of dynamic risk scoring, app settings inspector, and compliance', async ({ page, consoleErrors }) => {
  void consoleErrors;

  await page.setViewportSize({ width: 1440, height: 900 });

  // 1. About and Dynamic Scoring Rules
  await page.goto('/about');
  await page.waitForLoadState('networkidle');
  await expect(page.getByRole('heading', { name: 'About Rampart' })).toBeVisible({ timeout: 15000 });
  await expect(page.getByText('IN_KEV')).toBeVisible({ timeout: 15000 });

  await page.screenshot({
    path: path.join(ARTIFACT_DIR, 'dynamic_scoring_about_rules.png'),
    fullPage: false,
  });

  // Expand all rules to show CEL expressions
  const expandBtn = page.getByRole('button', { name: /expand all rules/i });
  if (await expandBtn.isVisible()) {
    await expandBtn.click();
    await page.waitForTimeout(500);
    await page.screenshot({
      path: path.join(ARTIFACT_DIR, 'dynamic_scoring_about_rules_expanded.png'),
      fullPage: false,
    });
  }

  // 2. Application Settings Read-Only Inspector with Dynamic Attributes & Score Breakdown
  await page.goto('/applications');
  await page.waitForLoadState('networkidle');
  const appRow = page.getByRole('row', { name: /Checkout/i });
  await expect(appRow).toBeVisible({ timeout: 15000 });
  await appRow.click();
  await page.waitForLoadState('networkidle');

  // Go to Settings tab
  const settingsTab = page.getByRole('tab', { name: 'Settings' });
  await expect(settingsTab).toBeVisible({ timeout: 15000 });
  await settingsTab.click();
  await page.waitForLoadState('networkidle');

  // Wait for settings section to appear
  await expect(page.getByTestId('app-settings-section')).toBeVisible({ timeout: 15000 });
  await page.waitForTimeout(500);

  await page.screenshot({
    path: path.join(ARTIFACT_DIR, 'application_settings_dynamic_inspector.png'),
    fullPage: false,
  });

  // 3. Compliance Route Verification
  await page.goto('/compliance');
  await page.waitForLoadState('networkidle');
  await expect(page.getByRole('heading', { name: 'Compliance' })).toBeVisible({ timeout: 15000 });
  await page.waitForTimeout(500);

  await page.screenshot({
    path: path.join(ARTIFACT_DIR, 'compliance_overview_healthy.png'),
    fullPage: false,
  });
});
