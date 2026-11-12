import { expect, test } from './fixtures';

// docs/16 D60: proof files are listed as downloads and can be attached by the person who asked.
test('the proof of a risk acceptance is listed, and a file can be attached', async ({ page, consoleErrors }) => {
  void consoleErrors;
  await page.goto('/workflow?sel=ra-31');
  const detail = page.getByRole('complementary', { name: 'Risk acceptance details' });
  const pdf = detail.getByRole('link', { name: 'CISO approval - payments admin.pdf' });
  await expect(pdf).toHaveAttribute('href', '/api/v1/risk-acceptances/ra-31/proofs/p1');
  await expect(pdf).toHaveAttribute('download', 'CISO approval - payments admin.pdf');
  await expect(detail.getByRole('link')).toHaveCount(2);

  await detail.getByLabel('Attach a file').setInputFiles({ name: 'minutes.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.7 minutes') });
  await expect(page.getByText('File attached')).toBeVisible();
  await expect(detail.getByRole('link')).toHaveCount(3);
});
