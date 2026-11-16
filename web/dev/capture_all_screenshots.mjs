/* global window, document */
import { spawn } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { chromium } from '@playwright/test';

const OUT_DIR = '/home/taha/Desktop/rampart_screenshots';
mkdirSync(OUT_DIR, { recursive: true });

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

async function setScenario(s) {
  try {
    await fetch(`http://127.0.0.1:8099/__mock/scenario?set=${s}`);
  } catch (e) {
    console.error('Failed to set scenario:', e);
  }
  await new Promise((r) => setTimeout(r, 200));
}

async function run() {
  console.log('--- Starting Mock Server & Vite Preview Server ---');
  const mockProc = spawn('node', ['dev/mock-server.mjs'], {
    cwd: process.cwd(),
    stdio: 'ignore',
  });
  const viteProc = spawn('npx', ['vite', 'preview', '--port', '5173'], {
    cwd: process.cwd(),
    stdio: 'ignore',
  });

  try {
    console.log('Waiting for servers to be ready...');
    await waitHttp('http://127.0.0.1:8099/api/v1/ui-config');
    await waitHttp('http://localhost:5173/');
    console.log('Servers are ready!');

    console.log('Launching Chromium...');
    const browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });

    const context = await browser.newContext({
      viewport: { width: 1440, height: 900 },
      deviceScaleFactor: 2,
    });
    const page = await context.newPage();

    async function snap(name, waitMs = 500) {
      await page.waitForTimeout(waitMs);
      const filePath = `${OUT_DIR}/${name}`;
      await page.screenshot({ path: filePath, fullPage: false });
      console.log(`Saved: ${name}`);
    }

    // 1. Login Page (loggedout)
    console.log('1. Login Page');
    await setScenario('loggedout');
    await page.goto('http://localhost:5173/login', { waitUntil: 'networkidle' });
    await snap('01_login_page.png', 600);

    // Switch back to populated session
    await setScenario('populated');

    // 2. Executive Overview Dashboard
    console.log('2. Executive Overview Dashboard');
    await page.goto('http://localhost:5173/overview', { waitUntil: 'networkidle' });
    await snap('02_overview_executive_dashboard.png', 1000);

    // 3. Findings Table
    console.log('3. Findings Table');
    await page.goto('http://localhost:5173/findings', { waitUntil: 'networkidle' });
    await snap('03_findings_table.png', 1000);

    // 4. Finding Details Inspector
    console.log('4. Finding Details Inspector');
    const firstRow = page.locator('table[role="grid"] tbody tr').first();
    if (await firstRow.isVisible()) {
      await firstRow.click();
      await page.waitForTimeout(600);
      await snap('04_finding_details_docked_inspector.png', 600);
    }

    // 5. Finding Triage Actions / Modals
    console.log('5. Finding Triage Actions');
    const changeStateBtn = page.getByRole('button', { name: /change state/i }).first();
    if (await changeStateBtn.isVisible()) {
      await changeStateBtn.click();
      await page.waitForTimeout(600);
      await snap('05_finding_triage_dialog.png', 600);
      const cancelBtn = page.getByRole('button', { name: /cancel|close/i }).first();
      if (await cancelBtn.isVisible()) await cancelBtn.click();
      await page.waitForTimeout(400);
    }

    // 6. Ingestion Runs (Tab 1)
    console.log('6. Ingestion Runs');
    await page.goto('http://localhost:5173/ingestion', { waitUntil: 'networkidle' });
    await snap('06_ingestion_runs_table.png', 800);

    // 7. Ingestion Run Inspector with Parsing Errors
    console.log('7. Ingestion Run Inspector with Errors');
    await page.goto('http://localhost:5173/ingestion?sel=01a1ceb2-0d19-7c55-a2f6-6b14e7d3a001', { waitUntil: 'networkidle' });
    await snap('07_ingestion_run_inspector_errors.png', 800);

    // 8. Ingestion Upload Dialog
    console.log('8. Ingestion Upload Dialog');
    const uploadBtn = page.getByRole('button', { name: /upload report/i }).first();
    if (await uploadBtn.isVisible()) {
      await uploadBtn.click();
      await page.waitForTimeout(500);
      await snap('08_ingestion_upload_dialog.png', 500);
      const closeUpload = page.getByRole('button', { name: /close|cancel/i }).first();
      if (await closeUpload.isVisible()) await closeUpload.click();
      await page.waitForTimeout(400);
    }

    // 9. Dependency-Track View (Tab 2)
    console.log('9. Ingestion Dependency-Track View');
    const dtrackTab = page.getByRole('tab', { name: /dependency-track/i });
    if (await dtrackTab.isVisible()) {
      await dtrackTab.click();
      await page.waitForTimeout(800);
      await snap('09_ingestion_dependency_track.png', 600);
    }

    // 10. Parsers & Formats Catalog (Tab 3)
    console.log('10. Ingestion Parsers & Formats');
    const parsersTab = page.getByRole('tab', { name: /parsers & formats/i });
    if (await parsersTab.isVisible()) {
      await parsersTab.click();
      await page.waitForTimeout(800);
      await snap('10_ingestion_parsers_and_formats.png', 600);

      // 11. Parser Details Modal
      console.log('11. Parser Details Modal');
      const detailsBtn = page.getByRole('button', { name: 'Details' }).first();
      if (await detailsBtn.isVisible()) {
        await detailsBtn.click();
        await page.waitForTimeout(500);
        await snap('11_ingestion_parser_details_modal.png', 500);
        const closeParser = page.getByRole('button', { name: 'Close' }).first();
        if (await closeParser.isVisible()) await closeParser.click();
        await page.waitForTimeout(400);
      }

      // 12. Custom CEL Parser Modal
      console.log('12. Custom CEL Parser Modal');
      const celBtn = page.getByRole('button', { name: /\+ Custom CEL Parser/i });
      if (await celBtn.isVisible()) {
        await celBtn.click();
        await page.waitForTimeout(500);
        await snap('12_ingestion_custom_cel_mapping_modal.png', 500);
        const doneCel = page.getByRole('button', { name: 'Done' }).first();
        if (await doneCel.isVisible()) await doneCel.click();
        await page.waitForTimeout(400);
      }
    }

    // 13. Workflow: Risk Acceptances
    console.log('13. Workflow: Risk Acceptances');
    await page.goto('http://localhost:5173/workflow', { waitUntil: 'networkidle' });
    await snap('13_workflow_risk_acceptances.png', 800);

    // 14. Workflow: Acceptance Detail with Proofs
    console.log('14. Workflow: Acceptance Detail');
    const firstAcceptance = page.locator('table[role="grid"] tbody tr').first();
    if (await firstAcceptance.isVisible()) {
      await firstAcceptance.click();
      await page.waitForTimeout(600);
      await snap('14_workflow_acceptance_detail_proofs.png', 600);
    }

    // 15. Workflow: Held Closes
    console.log('15. Workflow: Held Closes');
    await page.goto('http://localhost:5173/workflow?tab=held_closes', { waitUntil: 'networkidle' });
    await snap('15_workflow_held_closes.png', 800);

    // 16. Workflow: Finding Groups
    console.log('16. Workflow: Finding Groups');
    await page.goto('http://localhost:5173/workflow?tab=groups', { waitUntil: 'networkidle' });
    await snap('16_workflow_finding_groups.png', 800);

    // 17. Applications Portfolio
    console.log('17. Applications Portfolio');
    await page.goto('http://localhost:5173/applications', { waitUntil: 'networkidle' });
    await snap('17_applications_portfolio.png', 800);

    // 18. Application Detail Summary
    console.log('18. Application Detail Summary');
    const firstApp = page.locator('table[role="grid"] tbody tr a, table tbody tr a').first();
    if (await firstApp.isVisible()) {
      await firstApp.click();
      await page.waitForTimeout(800);
      await snap('18_application_detail_summary.png', 600);
    } else {
      await page.goto('http://localhost:5173/applications/a0000001-0000-4000-8000-000000000001', { waitUntil: 'networkidle' });
      await snap('18_application_detail_summary.png', 600);
    }

    // 19. Compliance: OWASP Top 10
    console.log('19. Compliance: OWASP Top 10');
    await page.goto('http://localhost:5173/compliance', { waitUntil: 'networkidle' });
    await snap('19_compliance_owasp_top10.png', 800);

    // 20. Compliance: PCI DSS
    console.log('20. Compliance: PCI DSS');
    const pciOption = page.locator('select').first();
    if (await pciOption.isVisible()) {
      await pciOption.selectOption({ index: 1 });
      await page.waitForTimeout(800);
      await snap('20_compliance_pci_dss.png', 600);
    }

    // 21. Integrations: Connectors Catalog
    console.log('21. Integrations: Connectors Catalog');
    await page.goto('http://localhost:5173/integrations', { waitUntil: 'networkidle' });
    await snap('21_integrations_connectors.png', 800);

    // 22. Integrations: New Connector Catalogue Dialog
    console.log('22. Integrations: New Connector Catalogue Dialog');
    const newConnectorBtn = page.getByRole('button', { name: /\+ New Connector/i });
    if (await newConnectorBtn.isVisible()) {
      await newConnectorBtn.click();
      await page.waitForTimeout(600);
      await snap('22_integrations_new_connector_modal.png', 600);
      const closeConn = page.getByRole('button', { name: /close|cancel/i }).first();
      if (await closeConn.isVisible()) await closeConn.click();
      await page.waitForTimeout(400);
    }

    // 23. Integrations: API Tokens Tab
    console.log('23. Integrations: API Tokens Tab');
    const tokensTab = page.getByRole('tab', { name: /api tokens/i });
    if (await tokensTab.isVisible()) {
      await tokensTab.click();
      await page.waitForTimeout(600);
      await snap('23_integrations_api_tokens.png', 600);
    }

    // 24. Inventory: Assets
    console.log('24. Inventory: Assets');
    await page.goto('http://localhost:5173/inventory', { waitUntil: 'networkidle' });
    await snap('24_inventory_monitored_assets.png', 800);

    // 25. Inventory: Components (SBOM)
    console.log('25. Inventory: Components (SBOM)');
    const componentsTab = page.getByRole('tab', { name: /sbom packages/i });
    if (await componentsTab.isVisible()) {
      await componentsTab.click();
      await page.waitForTimeout(600);
      await snap('25_inventory_components_sbom.png', 600);
    }

    // 26. Vulnerabilities: CVE Catalog
    console.log('26. Vulnerabilities: CVE Catalog');
    await page.goto('http://localhost:5173/vulnerabilities', { waitUntil: 'networkidle' });
    await snap('26_vulnerabilities_cve_catalog.png', 800);

    // 27. Administration: Access Control
    console.log('27. Administration: Access Control');
    await page.goto('http://localhost:5173/administration', { waitUntil: 'networkidle' });
    await snap('27_administration_access_control.png', 800);

    // 28. Administration: Audit Trail
    console.log('28. Administration: Audit Trail');
    await page.evaluate(() => {
      window.scrollTo(0, 480);
    });
    await snap('28_administration_audit_trail.png', 600);

    // 29. Notifications Popover
    console.log('29. Notifications Popover');
    await page.goto('http://localhost:5173/overview', { waitUntil: 'networkidle' });
    const bellBtn = page.getByRole('button', { name: /notifications/i }).first();
    if (await bellBtn.isVisible()) {
      await bellBtn.click();
      await page.waitForTimeout(500);
      await snap('29_shell_notifications_popover.png', 500);
    }

    // 30. Dark Mode: Executive Overview
    console.log('30. Dark Mode: Executive Overview');
    await page.evaluate(() => {
      document.documentElement.setAttribute('data-theme', 'dark');
      localStorage.setItem('rampart.theme', 'dark');
    });
    await page.waitForTimeout(400);
    await snap('30_dark_mode_overview.png', 600);

    // 31. Dark Mode: Findings & Inspector
    console.log('31. Dark Mode: Findings & Inspector');
    await page.goto('http://localhost:5173/findings', { waitUntil: 'networkidle' });
    await page.evaluate(() => {
      document.documentElement.setAttribute('data-theme', 'dark');
    });
    const darkFirstRow = page.locator('table[role="grid"] tbody tr').first();
    if (await darkFirstRow.isVisible()) {
      await darkFirstRow.click();
      await page.waitForTimeout(500);
    }
    await snap('31_dark_mode_findings_inspector.png', 600);

    // 32. Dark Mode: Parsers & Formats Catalog
    console.log('32. Dark Mode: Parsers & Formats');
    await page.goto('http://localhost:5173/ingestion', { waitUntil: 'networkidle' });
    await page.evaluate(() => {
      document.documentElement.setAttribute('data-theme', 'dark');
    });
    const darkParsersTab = page.getByRole('tab', { name: /parsers & formats/i });
    if (await darkParsersTab.isVisible()) {
      await darkParsersTab.click();
      await page.waitForTimeout(600);
    }
    await snap('32_dark_mode_parsers_and_formats.png', 600);

    console.log('--- ALL SCREENSHOTS CAPTURED SUCCESSFULLY! ---');
    await browser.close();
  } finally {
    console.log('Stopping servers...');
    mockProc.kill('SIGTERM');
    viteProc.kill('SIGTERM');
  }
}

run().catch((err) => {
  console.error('Fatal screenshot error:', err);
  process.exit(1);
});
