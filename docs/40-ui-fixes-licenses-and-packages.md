# 40. UI fixes: the Licenses and SBOM & Packages tabs

For the owner to read and fix. Nothing in this file is applied; a partial attempt was made and reverted at the owner's request (its patch is mentioned in section 8).
The same defects are item 25 of [docs/34](34-review-and-fix-plan.md); this file is the working copy, with the code to change.

Where: the application page, tabs **Licenses** (`web/src/routes/applications/ApplicationLicensesSection.tsx`) and **SBOM & Packages**
(`web/src/routes/applications/ApplicationSBOMSection.tsx`). Seen on the dev cluster on 2026-11-20, application `flare-reminders`
(289 packages, 11 licences).

## 1. What the screenshots show

| Screenshot | What is wrong |
|---|---|
| Licenses | The **Risk Category** column is a solid teal rectangle on every row, with no word, except `MIT OR GPL-3.0-or-later` (an orange rectangle) and `Unknown` (the only one with text). The four cards are coloured numbers (teal, orange). |
| SBOM & Packages | The **License** column is a teal rectangle with no licence name (`Unknown` is the only readable one). The table runs off the right edge (the **Actions** column is clipped). The **Asset / Target** column is the same truncated text on every row. Red is used in five places. The header button says "Refresh from Dependency-Track". |

## 2. The cause of the invisible words (L1 and L2)

The text and the background are the **same colour token**, so the word is there but cannot be seen:

```tsx
// ApplicationLicensesSection.tsx:269-271  (the Risk Category pill)
'bg-resolved text-resolved border border-resolved'     // permissive: teal on teal
'bg-high text-high border border-high'                 // copyleft:   orange on orange
// the third branch uses the raw zinc palette, not a token, and it is the one that reads:
'bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300 ...'

// ApplicationSBOMSection.tsx:394-395  (the License cell)
? 'bg-high text-high border border-high'
: 'bg-resolved text-resolved border border-resolved'
```

Why the tests did not catch it: `application_licenses_graph.test.tsx:121-122` asks for the text `Copyleft` and `Permissive` in the DOM, and it **is** in
the DOM; a test in jsdom does not see colour. Section 6 adds a test that can.

## 3. What to change, in order

### 3.1 The Risk Category column (L1) and the cards (L3)

Replace the pill with a word. Only copyleft gets a mark (a warning triangle), the rest is plain text. Put the component in `ApplicationLicensesSection.tsx`:

```tsx
import { IconWarning } from '@/components/icons';

export function LicenseRiskMark({ risk }: { risk: LicenseRisk }) {
  if (risk === 'copyleft') {
    return (
      <span className="inline-flex items-center gap-1.5 text-13 font-medium text-ink">
        <IconWarning className="size-3.5 shrink-0 text-high" />
        Copyleft
      </span>
    );
  }
  return <span className="text-13 text-ink-2">{risk === 'permissive' ? 'Permissive' : 'Unknown'}</span>;
}
```

and in the row use `<LicenseRiskMark risk={group.risk} />` where the `<span className={...rounded-full...}>` is. The two cards `text-resolved` and `text-high`
(lines 196 and 202) become `text-ink`.

### 3.2 The License cell in the packages table (L2)

Plain mono text; the same triangle, with an accessible name, only for copyleft. Use the one classifier (3.5) instead of the list written in the cell:

```tsx
{pkg.license && pkg.license.trim() !== '' ? (
  <span className="inline-flex items-center gap-1.5">
    <span className="font-mono text-12 text-ink">{pkg.license}</span>
    {classifyLicenseRisk(pkg.license) === 'copyleft' && (
      <IconWarning className="size-3.5 shrink-0 text-high" role="img" aria-label="Copyleft licence" />
    )}
  </span>
) : (
  <span className="text-12 text-ink-3">Unknown</span>
)}
```

Import `classifyLicenseRisk` from `./ApplicationLicensesSection`; the Licenses file imports only a **type** from the SBOM file, so there is no import cycle.
Add `IconWarning` to the icons import of the SBOM file.

### 3.3 The table that is cut off (P1)

Wrap the table in a scroll container:

```tsx
<div className="overflow-x-auto">
  <Table aria-label="Application packages table"> ... </Table>
</div>
```

### 3.4 The Asset / Target column (P2)

It says nothing when the application has one asset. Show it only when it has more than one:

```tsx
const manyAssets = new Set(packages.map((p) => p.asset_id ?? p.asset_name ?? '')).size > 1;
// header:  {manyAssets && <Th>Asset / Target</Th>}
// row:     {manyAssets && (<Td ...>...</Td>)}      // pass manyAssets to PackageRowGroup
```

The expanded row has `<Td colSpan={7}>` (`ApplicationSBOMSection.tsx:456`): make it `colSpan={manyAssets ? 7 : 6}`.

### 3.5 One licence classifier (L4)

`classifyLicenseRisk` guesses by substring and the list is written twice (in the Licenses file, and in the SBOM cell). Known wrong answers:

| Licence | Today | Should be |
|---|---|---|
| `Limited ...` (contains `mit`) | permissive | unknown |
| `Miscellaneous` (contains `isc`) | permissive | unknown |
| `Simple ...` (contains `mpl`) | copyleft | unknown |
| `MIT OR GPL-3.0-or-later` | copyleft (whole) | an `OR` is the choice of the one who uses it: permissive, noting the option |
| `MIT AND Zlib` | permissive | permissive |
| `MIT AND GPL-2.0-only` | copyleft | copyleft (an `AND` takes the strictest) |

Suggested: read the SPDX expression (split on `OR` and `AND`, strip parentheses and `WITH` exceptions), look each id up in a **table of SPDX ids**
(`MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `0BSD`, `Unlicense`, `Zlib`, `MIT-X11`... permissive; the `GPL-*`, `AGPL-*`, `LGPL-*`, `MPL-*`, `EPL-*`,
`CDDL-*`, `SSPL-*`, `OSL-*` families copyleft), and call anything not in the table `unknown`. Keep it in one file (for example `web/src/lib/license.ts`) and import it in both tabs.
Add a unit test per row of the table above.

### 3.6 The buttons that do nothing (P3)

- Header **"Refresh from Dependency-Track"** calls `POST /api/v1/applications/{id}/refresh-vulnerabilities`, which answers `202` and queues nothing
  (`internal/query/app_refresh.go`, docs/34 item 23). Dependency-Track no longer exists in the system. Rename it to **Check again** and make the endpoint real
  (docs/39, slice A) or remove the button until it is.
- Per-row **"Re-evaluate"** calls `POST /api/v1/inventory/components/scan`, which re-scores the tenant's findings; it does not match the package again (D126).
  Remove it, or rename it to what it does ("Re-score").

### 3.7 Too much red (P4)

Red (`critical`) is for risk, and these are findings counts, so red is allowed on **the number of open CVEs of a row** and the application's open-findings
count. It is also used for the "5 packages in this application have active CVEs" line, the CVE button background on each row, the dismiss bar and the status message:
five reds on one screen. Keep it on the row's count; make the rest ink. The status bar (`ApplicationSBOMSection.tsx:245-246`) can be a neutral bar with the
word "Failed" for a failure, red text only for the failure.

## 4. Tests to change

| File | Why |
|---|---|
| `routes/applications/application_licenses_graph.test.tsx:120-122` | It looks for `Copyleft` and `Permissive` as text; with the new component `Permissive` is still plain text and `Copyleft` has a mark. Keep it, and add: the `Copyleft` mark has an accessible name; the cards have no colour class. |
| `routes/applications/application_sbom_attest.test.tsx` | It uses the packages table; check it still finds the rows after the Asset column becomes conditional, and add a case with two assets (the column shows) and one asset (it does not). |
| new `lib/license.test.ts` | One case per row of the table in 3.5. |
| new `styles/colourPairs.test.ts` | Section 6. |

## 5. Verify, as `AGENTS.md` section 5 asks

```
cd web && bun run typecheck && bun run lint && bun run build && bun run test
```

then open the application page on the dev server (or `node dev/mock-server.mjs` with `npx vite`) and look at both tabs at 1440 px and 390 px: every licence
readable, the table scrolls instead of being cut, at most one red per row.

## 6. A test that cannot come back unseen

A word that cannot be read is invisible to jsdom, so the guard has to read the source. Add `web/src/styles/colourPairs.test.ts`:

```ts
import { describe, expect, it } from 'vitest';

const files = import.meta.glob('../**/*.tsx', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;

/** Every class list ("..." or `...` in a className) that holds bg-X and text-X of the same colour. */
function samePair(src: string): string[] {
  const out: string[] = [];
  for (const m of src.matchAll(/(["'`])((?:(?!\1).)*?\bbg-[a-z0-9-]+\b(?:(?!\1).)*?)\1/g)) {
    const list = m[2]!;
    for (const bg of list.matchAll(/\bbg-([a-z0-9-]+)(?:\/[0-9]+)?\b/g)) {
      // (?![\\w-]) so that text-accent-contrast is not read as text-accent
      if (new RegExp(`(?<![\\w-])text-${bg[1]}(?![\\w-])`).test(list) && !new RegExp(`(?<![\\w-])bg-${bg[1]}/[0-9]+`).test(list)) out.push(list.trim());
    }
  }
  return out;
}

describe('colour pairs', () => {
  it('no element has text and background of the same colour', () => {
    const bad = Object.entries(files)
      .filter(([f]) => !f.endsWith('.test.tsx'))
      .flatMap(([f, src]) => samePair(src).map((l) => `${f}: ${l}`));
    expect(bad).toEqual([]);
  });

  it('uses the colour tokens, not the raw zinc, slate or gray palettes', () => {
    const bad = Object.entries(files)
      .filter(([f]) => !f.endsWith('.test.tsx'))
      .filter(([, src]) => /\b(?:bg|text|border)-(?:zinc|slate|gray|neutral|stone)-\d{2,3}\b/.test(src))
      .map(([f]) => f);
    expect(bad).toEqual([]);
  });
});
```

A tinted background written with an opacity (`bg-resolved/10 text-resolved`, which is readable) is allowed by the second condition, and `text-accent-contrast`
on `bg-accent` is not a pair (the lookahead). **Run against the current source** (checked 2026-11-20) the first test reports exactly the four defects of this file
(`ApplicationLicensesSection.tsx`: `bg-resolved text-resolved`, `bg-high text-high`; `ApplicationSBOMSection.tsx`: the same two), and the second reports
`ApplicationLicensesSection.tsx` (the `zinc` classes). Both must be empty after the fix. If a later run reports something else, look at the page before silencing
the test.

## 7. Other things seen in the same screenshots, not defects of these two files

- The top-right **Open Findings: 34** and **Risk Score: 400** are coloured numbers; that is risk, so it is allowed.
- The packages table has 289 rows with no paging or virtualisation (docs/34 item 3 on the `limit=1000` fallback): it will be slow for a large SBOM.
- The package's purl is cut off under its name (`max-w-xs truncate`); the tooltip is the only way to read it whole. A copy button next to it would do.

## 8. The partial attempt

A first pass at 3.1, 3.2, 3.3 and 3.4 was written and then reverted. Its patch is at
`/tmp/claude-1000/-home-taha-Desktop-ourprojects-defectdojo/b6c58cdb-5c3e-4254-8bbe-7a209d837160/scratchpad/license-pills-partial.patch`
(temporary files can be cleared: copy it if you want it). `git apply` it to start from there; it does not include 3.5, 3.6, 3.7 or any test.
