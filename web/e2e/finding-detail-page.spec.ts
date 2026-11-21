import { expect, test } from './fixtures';
import path from 'node:path';
import fs from 'node:fs';

const ARTIFACT_DIR = process.env.ARTIFACT_DIR || path.join(__dirname, '..', 'test-results');
if (!fs.existsSync(ARTIFACT_DIR)) {
  fs.mkdirSync(ARTIFACT_DIR, { recursive: true });
}

test('capture screenshots of dedicated finding detail page (/findings/$id)', async ({ page, consoleErrors }) => {
  void consoleErrors;

  // Set crisp desktop viewport
  await page.setViewportSize({ width: 1440, height: 1000 });

  // Navigate directly to the dedicated finding detail page
  await page.goto('/findings/f0000000-0000-4000-8000-000000000001');
  await page.waitForLoadState('networkidle');

  // Verify page loaded with finding title and id
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible({ timeout: 10000 });
  await expect(page.getByText('Concrete Scanner Occurrences & Dynamic Evidence')).toBeVisible();

  // Screenshot 1: Overview with Scanner Evidence & Occurrences tab active
  await page.screenshot({
    path: path.join(ARTIFACT_DIR, 'finding_detail_page_overview.png'),
    fullPage: false,
  });

  // Switch to Tab 2: Technical Details & Location
  const technicalTab = page.getByRole('tab', { name: /Technical Details & Location/i });
  await expect(technicalTab).toBeVisible();
  await technicalTab.click();
  await expect(page.getByText('Technical Location & Code Context')).toBeVisible();

  // Screenshot 2: Technical Details & Location tab
  await page.screenshot({
    path: path.join(ARTIFACT_DIR, 'finding_detail_page_technical.png'),
    fullPage: false,
  });

  // Switch to Tab 3: Risk & Scoring Breakdown
  const riskTab = page.getByRole('tab', { name: /Risk & Scoring Breakdown/i });
  await expect(riskTab).toBeVisible();
  await riskTab.click();
  await expect(page.getByText('Total Computed Risk Score')).toBeVisible();

  // Screenshot 3: Risk & Scoring Breakdown tab
  await page.screenshot({
    path: path.join(ARTIFACT_DIR, 'finding_detail_page_risk.png'),
    fullPage: false,
  });

  // Switch to Tab 6: Raw Finding JSON
  const rawTab = page.getByRole('tab', { name: /Raw Finding JSON/i });
  await expect(rawTab).toBeVisible();
  await rawTab.click();
  await expect(page.getByRole('button', { name: /Copy Finding JSON/i })).toBeVisible();

  // Screenshot 4: Raw Finding JSON tab
  await page.screenshot({
    path: path.join(ARTIFACT_DIR, 'finding_detail_page_raw.png'),
    fullPage: false,
  });
});
