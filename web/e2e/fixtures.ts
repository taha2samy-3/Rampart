import { expect, test as base } from '@playwright/test';

/** Every test fails on a console error or an uncaught exception in the page. */
export const test = base.extend<{ consoleErrors: string[] }>({
  consoleErrors: async ({ page }, use) => {
    const errors: string[] = [];
    page.on('console', (m) => {
      if (m.type() === 'error') errors.push(m.text());
    });
    page.on('pageerror', (e) => errors.push(String(e)));
    await use(errors);
    expect(errors, 'console errors').toEqual([]);
  },
});
export { expect };
