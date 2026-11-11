import { useState } from 'react';
import {
  BAND_LABEL, BandShape, Button, CommandLine, Dialog, DialogContent, DialogTrigger, EmptyState, IconButton, IconCopy,
  Input, Kbd, Logo, ProblemMessage, ScoreBar, SearchField, Select, Skeleton, Spinner, Table, TBody, Td, Th, THead, Tr,
  Tabs, TabsContent, TabsList, TabsTrigger, Tooltip, useToast,
} from '@/components';
import type { ScoreBreakdown } from '@/api/types';
import { BANDS } from '@/lib/band';
import { useTheme, type ThemePreference } from '@/lib/theme';

const TOKENS: [string, string][] = [
  ['surface', 'Work surface'], ['chrome', 'Chrome'], ['ink', 'Text'], ['ink-2', 'Secondary text'], ['rule', 'Rule'],
  ['accent', 'Interactive'], ['resolved', 'Resolved'], ['band-critical', 'Critical'], ['band-high', 'High'],
  ['band-medium', 'Medium'], ['band-low', 'Low'], ['band-info', 'Info'], ['seg-severity', 'Severity segment'],
  ['seg-threat', 'Threat segment'], ['seg-context', 'Context segment'], ['seg-reduction', 'Reduction outline'],
];
const SAMPLE: ScoreBreakdown = {
  base_severity: 'critical', base_points: 600, total_score: 970, band: 'critical',
  factors: [{ name: 'KEV', points: 300, reason: '' }, { name: 'EPSS_HIGH', points: 150, reason: '' }, { name: 'INTERNET_FACING', points: 100, reason: '' }, { name: 'COMPENSATING_CONTROL', points: -80, reason: '' }],
};
const LOW: ScoreBreakdown = { base_severity: 'low', base_points: 80, total_score: 80, band: 'low', factors: [] };

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border-t border-rule py-5">
      <h2 className="mb-3 text-16 font-semibold">{title}</h2>
      {children}
    </section>
  );
}

/** Dev only. Every base component, in the current theme. */
export function Styleguide() {
  const { preference, setPreference } = useTheme();
  const toast = useToast();
  const [sel, setSel] = useState('b');
  return (
    <div className="mx-auto max-w-[960px] px-6 py-6">
      <header className="mb-4 flex items-center justify-between">
        <Logo size={28} />
        <Select
          label="Theme"
          value={preference}
          onValueChange={(v) => setPreference(v as ThemePreference)}
          options={[{ value: 'system', label: 'Match system' }, { value: 'light', label: 'Light' }, { value: 'dark', label: 'Dark' }]}
          className="w-36"
        />
      </header>
      <h1 className="display text-28">Style guide</h1>

      <Section title="Tokens">
        <ul className="m-0 grid list-none grid-cols-2 gap-x-6 gap-y-1 p-0 text-13 tablet:grid-cols-4">
          {TOKENS.map(([v, label]) => (
            <li key={v} className="flex items-center gap-2">
              <span className="size-5 border border-rule" style={{ background: `var(--${v})` }} aria-hidden="true" />
              <span>{label}</span>
            </li>
          ))}
        </ul>
      </Section>

      <Section title="Type">
        <div className="grid gap-1">
          <p className="display text-28">Page title, Red Hat Display 800 at 28</p>
          <p className="text-20 font-semibold">Heading at 20</p>
          <p className="text-16">Body large at 16</p>
          <p className="text-14">Interface text at 14</p>
          <p className="text-13">Table text at 13, scores like <span className="tnum font-semibold">950 905 880</span></p>
          <p className="text-12 text-ink-2">Secondary text at 12</p>
          <p className="font-mono text-13">risk:critical,high state:open age:&gt;30d</p>
        </div>
      </Section>

      <Section title="Buttons and fields">
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="primary">Continue with Default SSO</Button>
          <Button>Change state</Button>
          <Button variant="ghost">Cancel</Button>
          <Button loading>Saving</Button>
          <Button disabled>Disabled</Button>
          <Tooltip label="Copy"><IconButton label="Copy"><IconCopy /></IconButton></Tooltip>
          <Kbd>/</Kbd>
          <Kbd>j</Kbd>
        </div>
        <div className="mt-3 grid max-w-[520px] gap-2">
          <Input placeholder="Input" aria-label="Input" />
          <Input mono placeholder="risk:critical state:open" aria-label="Mono input" />
          <Input invalid defaultValue="invalid value" aria-label="Invalid input" />
          <SearchField shortcut="/" placeholder="Search" aria-label="Search" />
        </div>
      </Section>

      <Section title="Band shapes">
        <ul className="m-0 flex list-none flex-wrap gap-6 p-0 text-13">
          {BANDS.map((b) => (
            <li key={b} className="flex items-center gap-2">
              <BandShape band={b} size={16} />
              {BAND_LABEL[b]}
            </li>
          ))}
        </ul>
      </Section>

      <Section title="Score bar">
        <div className="grid max-w-[520px] gap-3">
          <ScoreBar breakdown={SAMPLE} score={970} size="full" />
          <div className="flex items-center gap-3 text-13"><span className="w-9 text-end font-semibold tnum">970</span><ScoreBar breakdown={SAMPLE} score={970} /></div>
          <div className="flex items-center gap-3 text-13"><span className="w-9 text-end font-semibold tnum">80</span><ScoreBar breakdown={LOW} score={80} /></div>
        </div>
      </Section>

      <Section title="Table">
        <Table aria-label="Sample">
          <THead><tr><Th>Finding</Th><Th>State</Th><Th align="end">Due</Th></tr></THead>
          <TBody>
            <Tr className="h-8"><Td>Hard-coded JWT signing secret</Td><Td>Open</Td><Td align="end">in 2d</Td></Tr>
            <Tr className="h-8" selected><Td className="shadow-[inset_3px_0_0_var(--accent)]">Prototype pollution in lodash.merge</Td><Td>Fixed</Td><Td align="end">3d late</Td></Tr>
            <Tr className="h-8"><Td>Missing HSTS preload directive</Td><Td>Open</Td><Td align="end">in 9d</Td></Tr>
          </TBody>
        </Table>
      </Section>

      <Section title="Tabs, menu, dialog, toast">
        <Tabs value={sel} onValueChange={setSel}>
          <TabsList label="Sample tabs">
            <TabsTrigger value="a">Overview</TabsTrigger>
            <TabsTrigger value="b">Evidence</TabsTrigger>
            <TabsTrigger value="c">Occurrences</TabsTrigger>
          </TabsList>
          <TabsContent value="a" className="py-3 text-13">Overview content.</TabsContent>
          <TabsContent value="b" className="py-3 text-13">Evidence content.</TabsContent>
          <TabsContent value="c" className="py-3 text-13">Occurrences content.</TabsContent>
        </Tabs>
        <div className="mt-2 flex gap-2">
          <Dialog>
            <DialogTrigger asChild><Button>Open dialog</Button></DialogTrigger>
            <DialogContent title="Accept risk until" description="Pick an expiry. Accepted findings return to the queue on that date.">
              <Button variant="primary">Accept risk</Button>
            </DialogContent>
          </Dialog>
          <Button onClick={() => toast.info('State changed')}>Show confirmation</Button>
          <Button onClick={() => toast.problem({ type: 'x', title: 'Failed to change state', status: 409, detail: 'Someone else changed this finding.', request_id: 'req_8f2c1a' })}>Show problem</Button>
        </div>
      </Section>

      <Section title="Feedback">
        <div className="flex items-center gap-4"><Spinner label="Loading" /><Skeleton className="h-3 w-40" /></div>
        <ProblemMessage className="mt-4" problem={{ type: 'x', title: 'Failed to list findings', status: 500, detail: 'The database did not answer within 5 s.', request_id: 'req_mock_a1b2c3' }} onRetry={() => {}} />
        <EmptyState className="px-0" title="No findings yet" action={<CommandLine command="rampart upload --source default semgrep.sarif" />}>
          Upload a report to see findings here.
        </EmptyState>
      </Section>
    </div>
  );
}
