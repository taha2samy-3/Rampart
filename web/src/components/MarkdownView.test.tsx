import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { MarkdownView } from './MarkdownView';

describe('MarkdownView component', () => {
  it('renders null when content is empty or null', () => {
    const { container } = render(<MarkdownView content="" />);
    expect(container.firstChild).toBeNull();
  });

  it('renders headings and inline code properly', () => {
    const md = `### Impact
A vulnerability in Multer versions < 2.1.0 allows an attacker to trigger DoS.

### Patches
Users should upgrade to \`2.1.0\`

### Workarounds
None`;

    render(<MarkdownView content={md} />);

    expect(screen.getByRole('heading', { level: 4, name: 'Impact' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 4, name: 'Patches' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 4, name: 'Workarounds' })).toBeInTheDocument();
    expect(screen.getByText(/A vulnerability in Multer versions < 2.1.0/)).toBeInTheDocument();
    expect(screen.getByText('2.1.0')).toHaveClass('font-mono');
  });

  it('renders unordered and ordered lists', () => {
    const md = `### References
- https://github.com/expressjs/multer/pull/123
- https://nvd.nist.gov/vuln/detail/CVE-2026-2359

1. First step
2. Second step`;

    render(<MarkdownView content={md} />);

    const listItems = screen.getAllByRole('listitem');
    expect(listItems.length).toBe(4);
    expect(screen.getByRole('link', { name: 'https://github.com/expressjs/multer/pull/123' })).toHaveAttribute(
      'href',
      'https://github.com/expressjs/multer/pull/123'
    );
  });

  it('prevents javascript: URLs in markdown links', () => {
    const md = `[Attack](javascript:alert('xss')) and [Safe](https://example.com)`;

    render(<MarkdownView content={md} />);

    expect(screen.queryByRole('link', { name: 'Attack' })).toBeNull();
    expect(screen.getByText(/Attack/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Safe' })).toHaveAttribute('href', 'https://example.com');
  });

  it('renders code blocks and blockquotes', () => {
    const md = `> Note: Important security advisory

\`\`\`json
{ "fixed": true }
\`\`\``;

    render(<MarkdownView content={md} />);

    expect(screen.getByText(/Note: Important security advisory/)).toBeInTheDocument();
    expect(screen.getByText('{ "fixed": true }')).toBeInTheDocument();
  });
});
