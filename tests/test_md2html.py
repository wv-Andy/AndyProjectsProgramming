"""Tests for the Markdown to HTML converter."""

from __future__ import annotations


def test_headings(md2html):
    assert md2html.convert("# Title") == "<h1>Title</h1>"
    assert md2html.convert("### Third") == "<h3>Third</h3>"


def test_paragraph(md2html):
    assert md2html.convert("Just some text.") == "<p>Just some text.</p>"


def test_bold_and_italic(md2html):
    assert md2html.convert("**bold**") == "<p><strong>bold</strong></p>"
    assert md2html.convert("*italic*") == "<p><em>italic</em></p>"


def test_inline_code(md2html):
    assert md2html.convert("`code`") == "<p><code>code</code></p>"


def test_link(md2html):
    assert md2html.convert("[text](https://example.com)") == (
        '<p><a href="https://example.com">text</a></p>'
    )


def test_unordered_list(md2html):
    html = md2html.convert("- one\n- two")
    assert html == "<ul>\n<li>one</li>\n<li>two</li>\n</ul>"


def test_ordered_list(md2html):
    html = md2html.convert("1. first\n2. second")
    assert html == "<ol>\n<li>first</li>\n<li>second</li>\n</ol>"


def test_switching_list_type_closes_the_first(md2html):
    html = md2html.convert("- bullet\n1. number")
    assert "</ul>" in html and "<ol>" in html


def test_fenced_code_block(md2html):
    html = md2html.convert("```python\nprint('hi')\n```")
    assert '<pre><code class="language-python">' in html
    assert "print('hi')" in html
    assert html.endswith("</code></pre>")


def test_code_block_content_is_not_formatted(md2html):
    """Markup inside a fence is literal, not converted."""
    html = md2html.convert("```\n**not bold**\n```")
    assert "**not bold**" in html
    assert "<strong>" not in html


def test_blockquote(md2html):
    html = md2html.convert("> quoted")
    assert html == "<blockquote>\n<p>quoted</p>\n</blockquote>"


def test_horizontal_rule(md2html):
    assert md2html.convert("---") == "<hr>"


def test_html_is_escaped(md2html):
    """A script tag must become inert text, not a live element."""
    html = md2html.convert("<script>alert(1)</script>")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_escaping_happens_before_formatting(md2html):
    html = md2html.convert("**<b>**")
    assert "<strong>&lt;b&gt;</strong>" == html.replace("<p>", "").replace("</p>", "")


def test_blank_lines_separate_paragraphs(md2html):
    html = md2html.convert("one\n\ntwo")
    assert html.count("<p>") == 2


def test_full_page_wraps_the_fragment(md2html):
    page = md2html.convert_page("# Hi", title="Test")
    assert "<!DOCTYPE html>" in page
    assert "<title>Test</title>" in page
    assert "<h1>Hi</h1>" in page


def test_mixed_document(md2html):
    source = "# Title\n\nA paragraph with **bold**.\n\n- item one\n- item two\n"
    html = md2html.convert(source)
    assert "<h1>Title</h1>" in html
    assert "<strong>bold</strong>" in html
    assert "<ul>" in html and "</ul>" in html
