"""A small Markdown to HTML converter, written as a line-oriented state machine.

It supports the common subset: headings, paragraphs, bold and italic, inline
code, links, fenced code blocks, unordered and ordered lists, and blockquotes.
It is not a full CommonMark implementation; it is an exercise in parsing, state
and escaping.

The one rule that matters for safety: text is HTML-escaped, so a document
containing `<script>` produces inert text, not a live tag.
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from collections.abc import Sequence

HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
UNORDERED = re.compile(r"^[-*+]\s+(.*)$")
ORDERED = re.compile(r"^\d+\.\s+(.*)$")
FENCE = re.compile(r"^```(\w*)$")
BLOCKQUOTE = re.compile(r"^>\s?(.*)$")
HORIZONTAL_RULE = re.compile(r"^(-{3,}|\*{3,}|_{3,})$")

# Inline patterns, applied after escaping so the source markup still matches.
LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
BOLD = re.compile(r"\*\*([^*]+)\*\*")
ITALIC = re.compile(r"(?<!\*)\*([^*]+)\*(?!\*)")
INLINE_CODE = re.compile(r"`([^`]+)`")


def render_inline(text: str) -> str:
    """Escape text, then apply inline formatting to the safe result."""
    escaped = html.escape(text, quote=False)
    # Links first, so their contents are not mangled by the other rules.
    escaped = LINK.sub(r'<a href="\2">\1</a>', escaped)
    escaped = BOLD.sub(r"<strong>\1</strong>", escaped)
    escaped = ITALIC.sub(r"<em>\1</em>", escaped)
    escaped = INLINE_CODE.sub(r"<code>\1</code>", escaped)
    return escaped


class Converter:
    """Holds the state a line-by-line parse needs: open lists, quotes, fences."""

    def __init__(self) -> None:
        self.output: list[str] = []
        self.list_type: str | None = None  # "ul", "ol" or None
        self.in_blockquote = False
        self.in_code = False
        self.code_language = ""

    def close_list(self) -> None:
        if self.list_type:
            self.output.append(f"</{self.list_type}>")
            self.list_type = None

    def close_blockquote(self) -> None:
        if self.in_blockquote:
            self.output.append("</blockquote>")
            self.in_blockquote = False

    def close_blocks(self) -> None:
        self.close_list()
        self.close_blockquote()

    def open_list(self, kind: str) -> None:
        if self.list_type != kind:
            self.close_list()
            self.output.append(f"<{kind}>")
            self.list_type = kind

    def feed(self, line: str) -> None:
        # A code fence swallows everything until it closes, verbatim.
        fence = FENCE.match(line)
        if self.in_code:
            if line.strip() == "```":
                self.output.append("</code></pre>")
                self.in_code = False
            else:
                self.output.append(html.escape(line, quote=False))
            return
        if fence:
            self.close_blocks()
            self.in_code = True
            self.code_language = fence.group(1)
            language = f' class="language-{self.code_language}"' if self.code_language else ""
            self.output.append(f"<pre><code{language}>")
            return

        stripped = line.rstrip()

        if not stripped:
            self.close_blocks()
            return

        if HORIZONTAL_RULE.match(stripped):
            self.close_blocks()
            self.output.append("<hr>")
            return

        heading = HEADING.match(stripped)
        if heading:
            self.close_blocks()
            level = len(heading.group(1))
            self.output.append(f"<h{level}>{render_inline(heading.group(2))}</h{level}>")
            return

        unordered = UNORDERED.match(stripped)
        if unordered:
            self.close_blockquote()
            self.open_list("ul")
            self.output.append(f"<li>{render_inline(unordered.group(1))}</li>")
            return

        ordered = ORDERED.match(stripped)
        if ordered:
            self.close_blockquote()
            self.open_list("ol")
            self.output.append(f"<li>{render_inline(ordered.group(1))}</li>")
            return

        quote = BLOCKQUOTE.match(stripped)
        if quote:
            self.close_list()
            if not self.in_blockquote:
                self.output.append("<blockquote>")
                self.in_blockquote = True
            self.output.append(f"<p>{render_inline(quote.group(1))}</p>")
            return

        # Anything else is a paragraph.
        self.close_blocks()
        self.output.append(f"<p>{render_inline(stripped)}</p>")

    def finish(self) -> str:
        if self.in_code:
            self.output.append("</code></pre>")
            self.in_code = False
        self.close_blocks()
        return "\n".join(self.output)


def convert(markdown: str) -> str:
    """Convert a Markdown string to an HTML fragment."""
    converter = Converter()
    for line in markdown.splitlines():
        converter.feed(line)
    return converter.finish()


PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
</head>
<body>
{body}
</body>
</html>
"""


def convert_page(markdown: str, title: str = "Document") -> str:
    return PAGE_TEMPLATE.format(title=html.escape(title), body=convert(markdown))


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert Markdown to HTML")
    parser.add_argument("input", help="Markdown file, or - for standard input")
    parser.add_argument("-o", "--output", help="Write HTML here instead of standard output")
    parser.add_argument("--full", action="store_true", help="Emit a full HTML page, not a fragment")
    parser.add_argument("--title", default="Document", help="Page title when using --full")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        if args.input == "-":
            markdown = sys.stdin.read()
        else:
            with open(args.input, encoding="utf-8") as handle:
                markdown = handle.read()
    except OSError as exc:
        print(f"[!] Could not read {args.input}: {exc}", file=sys.stderr)
        return 2

    html_output = convert_page(markdown, args.title) if args.full else convert(markdown)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(html_output)
        except OSError as exc:
            print(f"[!] Could not write {args.output}: {exc}", file=sys.stderr)
            return 2
        print(f"Wrote {args.output}")
    else:
        print(html_output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
