import { expect, test } from './fixtures';

// docs/13 section 5 and docs/16 D59: selection, the bulk bar and Edit, in a real browser.
test('select two findings, change them in bulk, and read what happened', async ({ page, consoleErrors }) => {
  void consoleErrors;
  await page.goto('/findings');
  const grid = page.getByRole('grid');
  const boxes = grid.getByRole('checkbox');
  await boxes.nth(0).check();
  await boxes.nth(1).check();
  await expect(page.getByText('2 selected')).toBeVisible();
  await expect(page.getByRole('button', { name: /Select all \d+ matching/ })).toBeVisible();

  await page.getByRole('button', { name: 'Change selected' }).click();
  const dialog = page.getByRole('dialog', { name: 'Change 2 findings' });
  await dialog.getByRole('combobox', { name: 'State' }).selectOption('under_investigation');
  await dialog.getByLabel('Owner').fill('mona@acme.example');
  await dialog.getByLabel('Add tags').fill('sprint-12');
  await dialog.getByRole('button', { name: 'Apply' }).click();
  await expect(dialog.getByRole('status')).toHaveText('2 changed, 0 already that way, 0 not changed');
  await dialog.getByRole('button', { name: 'Done' }).click();
  await expect(page.getByText('2 selected')).toHaveCount(0);

  // The first finding now shows its owner and tag in the inspector.
  await grid.getByRole('row').nth(1).click();
  const insp = page.getByRole('complementary', { name: 'Finding details' });
  await expect(insp.getByText('mona@acme.example')).toBeVisible();
  await expect(insp.getByText('sprint-12')).toBeVisible();
});

test('Edit (a) needs a reason for a new severity, then saves owner and severity', async ({ page, consoleErrors }) => {
  void consoleErrors;
  await page.goto('/findings');
  await page.getByRole('grid').getByRole('row').nth(2).click();
  await page.keyboard.press('a');
  const dialog = page.getByRole('dialog', { name: 'Edit finding' });
  const save = dialog.getByRole('button', { name: 'Save' });
  await expect(save).toBeDisabled();
  await dialog.getByRole('combobox', { name: 'Severity' }).selectOption('low');
  await expect(save).toBeDisabled();
  await dialog.getByLabel('Why the severity is different').fill('only reachable from the admin network');
  await dialog.getByLabel('Owner').fill('omar@acme.example');
  await save.click();
  await expect(page.getByText('Finding saved')).toBeVisible();
  const insp = page.getByRole('complementary', { name: 'Finding details' });
  await expect(insp.getByText('omar@acme.example')).toBeVisible();
  // Shown as a fact and again on the timeline.
  await expect(insp.getByText('only reachable from the admin network')).toHaveCount(2);
});

test('x selects the focused row from the keyboard', async ({ page, consoleErrors }) => {
  void consoleErrors;
  await page.goto('/findings');
  await page.getByRole('grid').getByRole('row').nth(1).click();
  await page.keyboard.press('x');
  await expect(page.getByText('1 selected')).toBeVisible();
  await page.getByRole('button', { name: 'Clear selection' }).click();
  await expect(page.getByText('1 selected')).toHaveCount(0);
});
