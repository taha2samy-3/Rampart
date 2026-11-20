import React from 'react';
import { cn } from '@/lib/cn';

interface MarkdownViewProps {
  content?: string | null;
  className?: string;
}

/** Only http(s) links are safe to open */
function isSafeUrl(url: string): boolean {
  return /^https?:\/\//i.test(url.trim());
}

/** Parses inline markdown formatting: code, bold, italic, links, and auto-detected URLs */
function renderInline(text: string): React.ReactNode[] {
  // Regex token matching:
  // 1: inline code `code`
  // 2: markdown link [text](url)
  // 3: raw http/https url
  // 4: bold **text** or __text__
  // 5: italic *text* or _text_
  const inlineRegex = /(`([^`]+)`)|(\[([^\]]+)\]\(([^)]+)\))|((https?:\/\/[^\s<]+[^\s<.,:;"')\]]))|(\*\*([^*]+)\*\*|__([^_]+)__)|(\*([^*]+)\*|_([^_]+)_)/g;

  const nodes: React.ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = inlineRegex.exec(text)) !== null) {
    // Append preceding raw text
    if (match.index > lastIndex) {
      nodes.push(text.slice(lastIndex, match.index));
    }

    const [full, , inlineCode, , linkText, linkUrl, , rawUrl, , boldAsterisks, boldUnderscores, , italicAsterisks, italicUnderscores] = match;

    if (inlineCode !== undefined) {
      nodes.push(
        <code
          key={`code-${match.index}`}
          className="rounded border border-rule bg-layer-2 px-1 py-0.5 font-mono text-12 text-ink"
        >
          {inlineCode}
        </code>
      );
    } else if (linkText !== undefined && linkUrl !== undefined) {
      const cleanUrl = linkUrl.trim();
      if (isSafeUrl(cleanUrl)) {
        nodes.push(
          <a
            key={`link-${match.index}`}
            href={cleanUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="text-accent hover:underline [overflow-wrap:anywhere]"
          >
            {renderInline(linkText)}
          </a>
        );
      } else {
        nodes.push(linkText);
      }
    } else if (rawUrl !== undefined) {
      const cleanUrl = rawUrl.trim();
      nodes.push(
        <a
          key={`rawurl-${match.index}`}
          href={cleanUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="text-accent hover:underline [overflow-wrap:anywhere]"
        >
          {cleanUrl}
        </a>
      );
    } else if (boldAsterisks !== undefined || boldUnderscores !== undefined) {
      const boldContent = boldAsterisks ?? boldUnderscores ?? '';
      nodes.push(
        <strong key={`bold-${match.index}`} className="font-semibold text-ink">
          {renderInline(boldContent)}
        </strong>
      );
    } else if (italicAsterisks !== undefined || italicUnderscores !== undefined) {
      const italicContent = italicAsterisks ?? italicUnderscores ?? '';
      nodes.push(
        <em key={`italic-${match.index}`} className="italic text-ink">
          {renderInline(italicContent)}
        </em>
      );
    } else {
      nodes.push(full);
    }

    lastIndex = match.index + full.length;
  }

  if (lastIndex < text.length) {
    nodes.push(text.slice(lastIndex));
  }

  return nodes.length === 0 ? [text] : nodes;
}

type Block =
  | { type: 'heading'; level: number; text: string }
  | { type: 'codeblock'; language?: string; code: string }
  | { type: 'blockquote'; lines: string[] }
  | { type: 'ul'; items: string[] }
  | { type: 'ol'; items: string[] }
  | { type: 'paragraph'; lines: string[] };

/** Parses plain markdown text into structured blocks */
function parseBlocks(content: string): Block[] {
  const rawLines = content.split(/\r?\n/);
  const blocks: Block[] = [];
  let i = 0;

  while (i < rawLines.length) {
    const line = rawLines[i];
    if (line === undefined) {
      i++;
      continue;
    }
    const trimmed = line.trim();

    // Empty line
    if (!trimmed) {
      i++;
      continue;
    }

    // Code block ```
    if (trimmed.startsWith('```')) {
      const language = trimmed.slice(3).trim();
      const codeLines: string[] = [];
      i++;
      while (i < rawLines.length) {
        const cur = rawLines[i];
        if (cur === undefined || cur.trim().startsWith('```')) break;
        codeLines.push(cur);
        i++;
      }
      if (i < rawLines.length) {
        const cur = rawLines[i];
        if (cur !== undefined && cur.trim().startsWith('```')) {
          i++;
        }
      }
      blocks.push({ type: 'codeblock', language: language || undefined, code: codeLines.join('\n') });
      continue;
    }

    // Headings #, ##, ###, ####, #####, ######
    const headingMatch = trimmed.match(/^(#{1,6})\s+(.+)$/);
    if (headingMatch && headingMatch[1] && headingMatch[2]) {
      blocks.push({
        type: 'heading',
        level: headingMatch[1].length,
        text: headingMatch[2].trim(),
      });
      i++;
      continue;
    }

    // Blockquote >
    if (trimmed.startsWith('>')) {
      const quoteLines: string[] = [];
      while (i < rawLines.length) {
        const cur = rawLines[i];
        if (cur === undefined || !cur.trim().startsWith('>')) break;
        quoteLines.push(cur.trim().replace(/^>\s?/, ''));
        i++;
      }
      blocks.push({ type: 'blockquote', lines: quoteLines });
      continue;
    }

    // Unordered list item (- or *)
    if (/^[-*]\s+/.test(trimmed)) {
      const items: string[] = [];
      while (i < rawLines.length) {
        const cur = rawLines[i];
        if (cur === undefined || !/^[-*]\s+/.test(cur.trim())) break;
        items.push(cur.trim().replace(/^[-*]\s+/, ''));
        i++;
      }
      blocks.push({ type: 'ul', items });
      continue;
    }

    // Ordered list item (1. 2. etc.)
    if (/^\d+\.\s+/.test(trimmed)) {
      const items: string[] = [];
      while (i < rawLines.length) {
        const cur = rawLines[i];
        if (cur === undefined || !/^\d+\.\s+/.test(cur.trim())) break;
        items.push(cur.trim().replace(/^\d+\.\s+/, ''));
        i++;
      }
      blocks.push({ type: 'ol', items });
      continue;
    }

    // Regular paragraph
    const pLines: string[] = [];
    while (i < rawLines.length) {
      const cur = rawLines[i];
      if (cur === undefined) break;
      const curTrim = cur.trim();
      if (
        curTrim === '' ||
        curTrim.startsWith('```') ||
        /^#{1,6}\s+/.test(curTrim) ||
        curTrim.startsWith('>') ||
        /^[-*]\s+/.test(curTrim) ||
        /^\d+\.\s+/.test(curTrim)
      ) {
        break;
      }
      pLines.push(curTrim);
      i++;
    }
    blocks.push({ type: 'paragraph', lines: pLines });
  }

  return blocks;
}

/**
 * Renders Markdown formatted text safely with React semantic elements.
 * Handles headings, code blocks, inline code, bold, italics, links, lists, and quotes.
 */
export function MarkdownView({ content, className }: MarkdownViewProps) {
  if (!content || !content.trim()) return null;

  const blocks = parseBlocks(content);

  return (
    <div className={cn('markdown-body space-y-2.5 text-13 text-ink [overflow-wrap:anywhere]', className)}>
      {blocks.map((block, idx) => {
        switch (block.type) {
          case 'heading': {
            const headingContent = renderInline(block.text);
            if (block.level === 1) {
              return (
                <h2 key={idx} className="mt-4 mb-2 text-16 font-bold tracking-tight text-ink">
                  {headingContent}
                </h2>
              );
            }
            if (block.level === 2) {
              return (
                <h3 key={idx} className="mt-3.5 mb-1.5 text-14 font-semibold tracking-tight text-ink">
                  {headingContent}
                </h3>
              );
            }
            if (block.level === 3) {
              return (
                <h4 key={idx} className="mt-3 mb-1 text-13 font-semibold tracking-tight text-ink">
                  {headingContent}
                </h4>
              );
            }
            return (
              <h5 key={idx} className="mt-2.5 mb-1 text-12 font-semibold uppercase tracking-wider text-ink-2">
                {headingContent}
              </h5>
            );
          }
          case 'codeblock':
            return (
              <pre
                key={idx}
                className="my-2 max-h-80 overflow-x-auto rounded border border-rule bg-layer-2 p-3 font-mono text-12 leading-relaxed text-ink"
              >
                <code>{block.code}</code>
              </pre>
            );
          case 'blockquote':
            return (
              <blockquote
                key={idx}
                className="my-2 border-l-2 border-accent pl-3 text-13 italic text-ink-2"
              >
                {block.lines.map((l, li) => (
                  <p key={li} className="m-0 leading-relaxed">
                    {renderInline(l)}
                  </p>
                ))}
              </blockquote>
            );
          case 'ul':
            return (
              <ul key={idx} className="my-1.5 list-disc space-y-1 pl-5 text-13 leading-relaxed text-ink">
                {block.items.map((it, itemIdx) => (
                  <li key={itemIdx}>{renderInline(it)}</li>
                ))}
              </ul>
            );
          case 'ol':
            return (
              <ol key={idx} className="my-1.5 list-decimal space-y-1 pl-5 text-13 leading-relaxed text-ink">
                {block.items.map((it, itemIdx) => (
                  <li key={itemIdx}>{renderInline(it)}</li>
                ))}
              </ol>
            );
          case 'paragraph': {
            const paragraphText = block.lines.join(' ');
            return (
              <p key={idx} className="m-0 leading-relaxed text-ink">
                {renderInline(paragraphText)}
              </p>
            );
          }
          default:
            return null;
        }
      })}
    </div>
  );
}
