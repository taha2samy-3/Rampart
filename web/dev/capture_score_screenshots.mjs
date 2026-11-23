import { spawn } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { chromium } from '@playwright/test';

const ARTIFACT_DIR = '/home/taha/.gemini/antigravity/brain/d93d25a6-e153-4f10-b53b-482a5ecb51d6';
const DESKTOP_DIR = '/home/taha/Desktop/rampart_screenshots';
mkdirSync(ARTIFACT_DIR, { recursive: true });
mkdirSync(DESKTOP_DIR, { recursive: true });

async function waitHttp(url, timeoutMs = 25000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url);
      if (res.ok) return true;
    } catch {
      // wait
    }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(`Timeout waiting for ${url}`);
}

async function run() {
  console.log('--- Starting Mock Server & Vite Preview ---');
  const mockProc = spawn('node', ['dev/mock-server.mjs'], {
    cwd: process.cwd(),
    stdio: 'ignore',
  });
  const viteProc = spawn('npx', ['vite', 'preview', '--port', '5173'], {
    cwd: process.cwd(),
    stdio: 'ignore',
  });

  const cleanup = () => {
    try { mockProc.kill(); } catch { /* ignore */ }
    try { viteProc.kill(); } catch { /* ignore */ }
  };
  process.on('exit', cleanup);
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  try {
    await waitHttp('http://127.0.0.1:8099/api/v1/ui-config');
    await waitHttp('http://localhost:5173/');
    console.log('Servers ready!');

    const browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });

    const context = await browser.newContext({
      viewport: { width: 1440, height: 960 },
      deviceScaleFactor: 2,
    });
    const page = await context.newPage();

    async function snap(name, waitMs = 500) {
      await page.waitForTimeout(waitMs);
      await page.screenshot({ path: `${ARTIFACT_DIR}/${name}`, fullPage: false });
      await page.screenshot({ path: `${DESKTOP_DIR}/${name}`, fullPage: false });
      console.log(`Saved: ${name}`);
    }

    async function snapElement(selector, name, waitMs = 300) {
      await page.waitForTimeout(waitMs);
      const el = page.locator(selector).first();
      if (await el.isVisible()) {
        await el.screenshot({ path: `${ARTIFACT_DIR}/${name}` });
        await el.screenshot({ path: `${DESKTOP_DIR}/${name}` });
        console.log(`Saved element: ${name}`);
      }
    }

    // Ensure session populated
    await fetch('http://127.0.0.1:8099/__mock/scenario?set=populated');

    // 1. Applications Portfolio Table
    console.log('1. Applications Portfolio');
    await page.goto('http://localhost:5173/applications', { waitUntil: 'networkidle' });
    await snap('01_applications_portfolio_table.png', 1000);

    // 2. Application Detail - Checkout (Critical Risk 1000)
    console.log('2. Application Detail - Checkout (Critical 1000)');
    await page.goto('http://localhost:5173/applications/a0000001-0000-4000-8000-000000000001', { waitUntil: 'networkidle' });
    await snap('02_application_checkout_overview.png', 1000);
    await snapElement('[data-testid="application-score-card"]', '03_application_checkout_score_card.png', 500);

    // 3. Application Detail - Billing (High Risk 650)
    console.log('3. Application Detail - Billing (High 650)');
    await page.goto('http://localhost:5173/applications/a0000001-0000-4000-8000-000000000002', { waitUntil: 'networkidle' });
    await snap('04_application_billing_overview.png', 1000);
    await snapElement('[data-testid="application-score-card"]', '05_application_billing_score_card.png', 500);

    // 4. Application Detail - Ledger (Clean / Zero Risk 0)
    console.log('4. Application Detail - Ledger (Clean 0)');
    await page.goto('http://localhost:5173/applications/a0000001-0000-4000-8000-000000000004', { waitUntil: 'networkidle' });
    await snap('06_application_ledger_clean_overview.png', 1000);
    await snapElement('[data-testid="application-score-card"]', '07_application_ledger_score_card.png', 500);

    await browser.close();
    console.log('All screenshots captured successfully!');
  } finally {
    cleanup();
  }
}

run().catch((err) => {
  console.error('Capture error:', err);
  process.exit(1);
});
