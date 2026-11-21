import { expect, test } from './fixtures';
import path from 'node:path';

const ARTIFACT_DIR = '/home/taha/.gemini/antigravity/brain/d93d25a6-e153-4f10-b53b-482a5ecb51d6';

test('capture screenshots of dynamic scanner evidence in finding inspector', async ({ page, consoleErrors }) => {
  void consoleErrors;

  // Set crisp desktop viewport
  await page.setViewportSize({ width: 1440, height: 900 });

  // Navigate to findings
  await page.goto('/findings');
  await page.waitForLoadState('networkidle');

  // Open inspector by clicking the first finding row
  const grid = page.getByRole('grid');
  await grid.getByRole('row').nth(1).click();

  const insp = page.getByRole('complementary', { name: 'Finding details' });
  await expect(insp).toBeVisible();

  // Scroll inspector to reveal Scanner Evidence
  const scannerEvidence = insp.getByText('Scanner Evidence');
  await expect(scannerEvidence).toBeVisible({ timeout: 10000 });
  await scannerEvidence.scrollIntoViewIfNeeded();

  // Wait for occurrence details to be rendered
  await expect(insp.getByText('rule-gitleaks:rec-4f918e')).toBeVisible();

  // Screenshot 1: Scanner Evidence overview with dynamic attributes
  await page.screenshot({
    path: path.join(ARTIFACT_DIR, 'scanner_evidence_dynamic_attributes.png'),
    fullPage: false,
  });

  // Expand Raw Scanner Record JSON viewer
  const rawToggle = insp.getByText('Raw Scanner Record (JSON)');
  await expect(rawToggle).toBeVisible();
  await rawToggle.click();

  // Wait for code viewer and Copy Raw JSON button
  await expect(insp.getByRole('button', { name: /Copy Raw JSON/i })).toBeVisible();

  // Screenshot 2: Raw Scanner Record JSON viewer expanded
  await page.screenshot({
    path: path.join(ARTIFACT_DIR, 'scanner_evidence_raw_json_viewer.png'),
    fullPage: false,
  });

  // Switch to the second scanner occurrence tab (Trivy)
  const trivyTab = insp.getByRole('button', { name: 'trivy' });
  if (await trivyTab.isVisible()) {
    await trivyTab.click();
    await expect(insp.getByText('trivy:vuln:CVE-2023-44487')).toBeVisible();

    // Screenshot 3: Multi-scanner tab evidence switcher
    await page.screenshot({
      path: path.join(ARTIFACT_DIR, 'scanner_evidence_multi_scanner_tabs.png'),
      fullPage: false,
    });
  }
});
