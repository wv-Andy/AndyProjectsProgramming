# Markdown to HTML Converter

Converts a useful subset of Markdown to HTML, written as a line-oriented state
machine. No dependencies.

Supports headings, paragraphs, bold, italic, inline code, links, fenced code
blocks, ordered and unordered lists, blockquotes and horizontal rules. It is not
a full CommonMark implementation; it is an exercise in parsing, state and
escaping.

## Usage

```bash
# A fragment to stdout
python md2html.py notes.md

# A full HTML page to a file
python md2html.py notes.md --full --title "My Notes" -o notes.html

# From a pipe
cat notes.md | python md2html.py -
```

## How it works

Markdown is parsed one line at a time, and the parser holds state between lines:
whether a list is open, whether a blockquote is open, whether it is inside a code
fence. Each line either continues the current block or closes it and starts a new
one. That state is the whole trick, because whether `- item` opens a list or
continues one depends on what came before it.

Inline formatting runs after block parsing, on already-escaped text.

## Escaping comes first

The security rule is that text is HTML-escaped **before** any formatting is
applied. A document containing `<script>alert(1)</script>` produces the inert
text `&lt;script&gt;...`, never a live tag. Because escaping happens first, the
Markdown markup itself still matches afterwards, so `**<b>**` correctly becomes
bold text containing the literal characters `<b>`.

A converter that formats first and escapes second, or never escapes at all, is an
XSS hole waiting for the first untrusted document.

## What I learned

- A line-oriented state machine, and why block context needs state
- The ordering problem: escape first, then format, or you get XSS
- Regular expressions for structured text, and their limits
- Why code fences need a mode that suppresses all other parsing

## License

MIT, see [LICENSE](../../LICENSE).
