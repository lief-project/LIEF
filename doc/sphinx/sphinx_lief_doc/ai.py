import hashlib
import json
import re
from collections import Counter
from html import escape
from pathlib import Path
from urllib.parse import quote, urldefrag, urljoin

from bs4 import BeautifulSoup, Tag
from markdown_it import MarkdownIt
from markdownify import MarkdownConverter
from sphinx.application import Sphinx
from sphinx.errors import ExtensionError
from sphinx.util import logging

logger = logging.getLogger(__name__)
PLAIN_PARSER = MarkdownIt("commonmark").enable("table")


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def serialize(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def plain_text(markdown: str) -> str:
    soup = BeautifulSoup(PLAIN_PARSER.render(markdown), "lxml")
    return " ".join(soup.get_text(" ", strip=True).split())


def inline_code(text: str) -> str:
    fence = "`" * (1 + max((len(x) for x in re.findall(r"`+", text)), default=0))
    return f"{fence} {text} {fence}"


class DocumentationMarkdown(MarkdownConverter):
    """Keep Sphinx signatures, code, tabs, and citation targets readable."""

    def __init__(self, canonical: str):
        super().__init__(heading_style="ATX", bullets="-", autolinks=False)
        self.canonical = canonical
        self.headings: dict[str, dict] = {}

    def escape(self, text, parent_tags):
        # Template arguments and comparison operators are text, not HTML tags.
        return super().escape(escape(text, quote=False), parent_tags)

    def heading(self, level: int, title: str, fragment: str, *, code=False) -> str:
        title = " ".join(title.split())
        url = self.canonical + (f"#{fragment}" if fragment else "")
        label = (
            inline_code(title)
            if code
            else self.escape(title, set()).replace("[", r"\[").replace("]", r"\]")
        )
        line = f"{'#' * level} [{label}](<{url}>)"
        self.headings[line] = {
            "heading": title,
            "headingLevel": level,
            "url": url,
        }
        return f"\n\n{line}\n\n"

    def convert_hN(self, n, el, text, parent_tags):
        fragment = el.get("id", "")
        if not fragment and el.parent.name == "section":
            fragment = el.parent.get("id", "")
        return self.heading(n, el.get_text(), fragment)

    def convert_dt(self, el, text, parent_tags):
        if "sig-object" not in el.get("class", ()) or not el.get("id"):
            return f"\n\n**{text.strip()}**\n\n"
        section = el.find_parent("section")
        title = (
            section.find(re.compile(r"^h[1-6]$"), recursive=False) if section else None
        )
        depth = int(title.name[1]) if title else 1
        depth = min(6, depth + len(el.find_parents("dl")))
        names = el.select(".sig-prename, .sig-name")
        name = "".join(node.get_text() for node in names) or el.get_text()
        return self.heading(depth, name, el["id"], code=True) + text.strip() + "\n\n"

    def convert_dd(self, el, text, parent_tags):
        # Definition-list indentation would turn nested API entries into code.
        return f"\n\n{text.strip()}\n\n"

    def convert_pre(self, el, text, parent_tags):
        code = el.get_text().rstrip("\n")
        language = ""
        for ancestor in [el, *el.parents]:
            for cls in ancestor.get("class", ()):
                if cls.startswith(("highlight-", "language-")):
                    language = cls.split("-", 1)[1]
                    break
            if language:
                break
        fence = "`" * max(
            3, 1 + max((len(x) for x in re.findall(r"`+", code)), default=0)
        )
        return f"\n\n{fence}{language}\n{code}\n{fence}\n\n"

    def convert_div(self, el, text, parent_tags):
        if "admonition" in el.get("class", ()):
            return (
                "\n\n"
                + "\n".join("> " + line for line in text.strip().splitlines())
                + "\n\n"
            )
        return super().convert_div(el, text, parent_tags)

    def convert_p(self, el, text, parent_tags):
        if "admonition-title" in el.get("class", ()):
            text = f"**{text.strip()}**"
        return super().convert_p(el, text, parent_tags)

    def convert_a(self, el, text, parent_tags):
        # Angle brackets preserve URLs containing parentheses in API anchors.
        href = el.get("href")
        if href:
            el["href"] = "<" + quote(href, safe="/:#?&=@+!$'()*;,%-._~") + ">"
        result = super().convert_a(el, text, parent_tags)
        if href:
            el["href"] = href
        return result

    def convert_td(self, el, text, parent_tags):
        return super().convert_td(el, text.replace("|", r"\|"), parent_tags)

    convert_th = convert_td

    def convert_table(self, el, text, parent_tags):
        # Markdown tables cannot represent row spans or nested tables.
        if el.select_one("[rowspan], table"):
            return f"\n\n{el}\n\n"
        return super().convert_table(el, text, parent_tags)


def prepare_article(soup: BeautifulSoup, canonical: str) -> Tag:
    article = soup.select_one("article.docs-content")
    if article is None:
        raise ExtensionError(f"AI export: missing documentation article in {canonical}")

    for panel in article.select('[role="tabpanel"]'):
        tab = article.find(id=panel.get("aria-labelledby", ""))
        if tab:
            label = soup.new_tag("p")
            label.append(soup.new_tag("strong"))
            label.strong.string = tab.get_text(" ", strip=True)
            panel.insert(0, label)

    for node in article.select(
        "script, style, .headerlink, .viewcode-link, .linenos, .lineno, "
        '.copybtn, [role="tablist"]'
    ):
        node.decompose()
    for table in article.select("table.highlighttable"):
        code = table.select_one(".highlight")
        if code:
            table.replace_with(code.extract())

    # Language menus contain real API links but their trigger is only a button.
    for menu in article.select(".dropdown-menu"):
        menu.name = "span"
        menu.insert(0, " (")
        for link in menu.select("a")[:-1]:
            link.insert_after("; ")
        menu.append(")")
    for trigger in article.select('a[data-toggle="dropdown"]'):
        trigger.unwrap()
    for dropdown in article.select(".dropdown"):
        dropdown.name = "span"

    for node in article.select("[href], [src]"):
        for attr in ("href", "src"):
            if node.get(attr):
                node[attr] = urljoin(canonical, node[attr])
    return article


def split_chunks(
    markdown: str, headings: dict[str, dict], document: dict
) -> list[dict]:
    chunks = []
    current = {
        "heading": document["title"],
        "headingLevel": 0,
        "url": document["canonical"],
    }
    path: list[tuple[int, str]] = []
    lines: list[str] = []
    fence = ""

    def flush():
        body = "\n".join(lines).strip()
        if not body:
            return
        fragment = urldefrag(current["url"])[1]
        key = f"fragment:{fragment}" if fragment else "document-root"
        chunks.append(
            {
                **document,
                **current,
                "chunkID": digest(f"{document['documentID']}:{key}"),
                "headingPath": [title for _, title in path],
                "markdown": body,
                "content": plain_text(body),
                "contentHash": digest(body),
            }
        )

    for line in markdown.splitlines():
        marker = re.match(r"^(`{3,}|~{3,})", line)
        if marker:
            run = marker[1]
            if not fence:
                fence = run
            elif (
                run[0] == fence[0]
                and len(run) >= len(fence)
                and not line[len(run) :].strip()
            ):
                fence = ""
        if not fence and line in headings:
            flush()
            lines = []
            current = headings[line]
            while path and path[-1][0] >= current["headingLevel"]:
                path.pop()
            path.append((current["headingLevel"], current["heading"]))
        lines.append(line)
    flush()
    for position, chunk in enumerate(chunks):
        chunk.update(
            position=position,
            documentChunkCount=len(chunks),
            previousChunkID=chunks[position - 1]["chunkID"] if position else "",
            nextChunkID=chunks[position + 1]["chunkID"]
            if position + 1 < len(chunks)
            else "",
        )
    return chunks


def markdown_document(document: dict, body: str) -> str:
    metadata = "\n".join(
        f"{key}: {serialize(value)}" for key, value in document.items()
    )
    return f"---\n{metadata}\n---\n\n{body}\n"


def validate_code_blocks(article: Tag, markdown: str, docname: str):
    expected = Counter(pre.get_text().rstrip("\n") for pre in article.select("pre"))
    actual = Counter()
    for token in PLAIN_PARSER.parse(markdown):
        if token.type in {"fence", "code_block"}:
            actual[token.content.rstrip("\n")] += 1
        elif token.type == "html_block":
            table = BeautifulSoup(token.content, "lxml")
            actual.update(pre.get_text().rstrip("\n") for pre in table.select("pre"))
    if expected - actual:
        raise ExtensionError(f"AI export: code blocks lost or changed in {docname}")


def llms_index(documents: list[dict], base_url: str, version: str, channel: str) -> str:
    lines = [
        "# LIEF documentation",
        "",
        "> LIEF parses, inspects, modifies, and writes executable formats in C++, Python, and Rust.",
        "",
        f"Documentation version: {version}. Channel: {channel}. Canonical documentation: {base_url}",
        "",
        (
            "Match these references to the installed LIEF version. The latest channel follows development; "
            "the stable channel documents the latest release. Check the installation and feature guides "
            "for platform, architecture, and build requirements."
        ),
        "",
        (
            "LIEF Extended adds debug information, Objective-C metadata, dyld shared cache, assembly, "
            "and disassembly features. Basic runtime support is an independent build option; runtime "
            "memory-layout enumeration, assembly, and disassembly require Extended."
        ),
        "",
        (
            "Each page has a resolved Markdown copy with absolute citation links, expanded code includes, "
            "all language tabs, and API signatures. The indexes cover this Sphinx documentation; separate "
            "Rustdoc and Doxygen sites are linked from the API guides. Use individual pages or chunks "
            "for targeted retrieval; llms-full.txt bundles every page and can be large."
        ),
        "",
        "## Machine-readable resources",
        "",
    ]
    for path, title, description in (
        (
            "index.json",
            "Document index",
            "Titles, descriptions, versions, Markdown URLs, and full text.",
        ),
        (
            "index.chunks.json",
            "Retrieval chunks",
            "Heading and API symbol chunks with citation URLs, stable IDs, hashes, and neighbours.",
        ),
        (
            "llms-full.txt",
            "Complete Markdown corpus",
            "Every exported document, including API references.",
        ),
        ("sitemap.xml", "Sitemap", "Canonical HTML pages in this documentation build."),
        (
            "objects.inv",
            "Sphinx symbol inventory",
            "Resolved cross-reference targets for documented APIs.",
        ),
    ):
        lines.append(f"- [{title}]({urljoin(base_url, path)}): {description}")

    groups: dict[str, list[dict]] = {
        name: []
        for name in (
            "Start here",
            "LIEF Extended",
            "Runtime",
            "Formats and API references",
            "Tutorials",
            "Plugins and tools",
            "Optional",
        )
    }
    for document in documents:
        name = document["docname"]
        if name in {"index", "intro", "installation", "compilation", "ai"}:
            group = "Start here"
        elif name.startswith("extended/"):
            group = "LIEF Extended"
        elif name.startswith("runtime/"):
            group = "Runtime"
        elif name.startswith(("formats/", "api/")):
            group = "Formats and API references"
        elif name.startswith("tutorials/"):
            group = "Tutorials"
        elif name.startswith(("plugins/", "tools/")):
            group = "Plugins and tools"
        else:
            group = "Optional"
        groups[group].append(document)
    for name, pages in groups.items():
        if pages:
            lines.extend(["", f"## {name}", ""])
            if name == "Start here":
                order = ["index", "intro", "installation", "compilation", "ai"]
                pages.sort(key=lambda page: order.index(page["docname"]))
            else:
                pages.sort(
                    key=lambda page: (
                        0 if page["docname"].endswith("/intro") else 1,
                        str(Path(page["docname"]).parent),
                        0 if page["docname"].endswith("/index") else 1,
                        page["docname"],
                    )
                )
            for page in pages:
                title = page["title"].replace("[", r"\[").replace("]", r"\]")
                lines.append(
                    f"- [{title}]({page['markdownURL']}): {page['description']}"
                )
    return "\n".join(lines) + "\n"


def add_discovery_links(app: Sphinx, pagename, templatename, context, doctree):
    if app.builder.name != "html" or pagename not in app.env.found_docs:
        return
    metadata = BeautifulSoup(context["metatags"], "lxml")
    if "noindex" in app.env.metadata.get(pagename, {}) or any(
        "noindex" in tag.get("content", "").lower()
        for tag in metadata.select('meta[name="robots"]')
    ):
        return
    canonical = context.get("canonical_url")
    if not canonical:
        raise ExtensionError(f"AI export: missing canonical URL for {pagename}")
    markdown_url = canonical.removesuffix(".html") + ".md"
    base_url = app.config.html_theme_options["base_url"]
    context["metatags"] += (
        f'\n<link rel="alternate" type="text/markdown" href="{escape(markdown_url, quote=True)}">'
        f'\n<link rel="describedby" type="text/plain" href="{escape(urljoin(base_url, "llms.txt"), quote=True)}">'
    )


def remove_purged_markdown(app: Sphinx, env, docname: str):
    if app.builder.name == "html":
        Path(app.builder.get_outfilename(docname)).with_suffix(".md").unlink(
            missing_ok=True
        )


def export_documentation(app: Sphinx, exception: Exception | None):
    if exception is not None or app.builder.name != "html":
        return
    output = Path(app.outdir)
    base_url = app.config.html_theme_options["base_url"]
    version = app.config.release
    channel = app.config.lief_doc_endpoint
    documents, chunks, full = [], [], []
    for docname in sorted(app.env.found_docs):
        html_path = Path(app.builder.get_outfilename(docname))
        soup = BeautifulSoup(html_path.read_text(encoding="utf-8"), "lxml")
        if any(
            "noindex" in tag.get("content", "").lower()
            for tag in soup.select('meta[name="robots"]')
        ):
            html_path.with_suffix(".md").unlink(missing_ok=True)
            continue
        canonical = soup.select_one('link[rel="canonical"]')["href"]
        markdown_url = canonical.removesuffix(".html") + ".md"
        for relation, media_type, url in (
            ("alternate", "text/markdown", markdown_url),
            ("describedby", "text/plain", urljoin(base_url, "llms.txt")),
        ):
            links = soup.find_all("link", rel=relation, type=media_type)
            if len(links) != 1 or links[0].get("href") != url:
                raise ExtensionError(f"AI export: invalid {relation} link in {docname}")
        document = {
            "documentID": digest(canonical),
            "docname": docname,
            "title": soup.title.get_text(),
            "description": soup.select_one('meta[name="description"]')["content"],
            "canonical": canonical,
            "markdownURL": markdown_url,
            "documentationVersion": version,
            "documentationChannel": channel,
            "language": app.config.language or "en",
        }
        converter = DocumentationMarkdown(canonical)
        article = prepare_article(soup, canonical)
        body = converter.convert_soup(article).strip()
        if not body:
            raise ExtensionError(f"AI export: empty Markdown for {docname}")
        validate_code_blocks(article, body, docname)
        document["contentHash"] = digest(body)
        markdown = markdown_document(document, body)
        html_path.with_suffix(".md").write_text(markdown, encoding="utf-8")
        page_chunks = split_chunks(body, converter.headings, document)
        chunks.extend(page_chunks)
        documents.append(
            {**document, "content": " ".join(chunk["content"] for chunk in page_chunks)}
        )
        full.append(markdown)

    for filename, records, key in (
        ("index.json", documents, "documents"),
        ("index.chunks.json", chunks, "chunks"),
    ):
        payload = {
            "schemaVersion": "1.0",
            "canonicalSite": base_url,
            "documentationVersion": version,
            "documentationChannel": channel,
            "documentCount": len(documents),
            "corpusHash": digest(serialize(records)),
            key: records,
        }
        if key == "chunks":
            payload.update(
                chunkCount=len(chunks),
                chunking={
                    "strategy": "html-heading-and-api-symbol",
                    "ordering": "docname ascending, then source order",
                    "identity": "documentID = SHA-256(canonical); chunkID = SHA-256(documentID + ':fragment:' + anchor), or ':document-root' without an anchor",
                    "contentHash": "SHA-256 of the UTF-8 Markdown body",
                    "corpusHash": "SHA-256 of the JSON records, including metadata, using Python json.dumps with ensure_ascii=False and sort_keys=True",
                    "navigation": "position is zero-based within a document; neighbour IDs are empty at document boundaries",
                },
            )
        (output / filename).write_text(serialize(payload) + "\n", encoding="utf-8")
    (output / "llms-full.txt").write_text("\n\n".join(full), encoding="utf-8")
    (output / "llms.txt").write_text(
        llms_index(documents, base_url, version, channel), encoding="utf-8"
    )
    counts = Counter(chunk["chunkID"] for chunk in chunks)
    duplicates = sorted(
        {chunk["url"] for chunk in chunks if counts[chunk["chunkID"]] > 1}
    )
    if duplicates:
        raise ExtensionError(
            "AI export: duplicate chunk IDs for " + ", ".join(duplicates)
        )
    logger.info(
        "Exported %d Markdown documents and %d retrieval chunks",
        len(documents),
        len(chunks),
    )


def setup(app: Sphinx):
    app.connect("html-page-context", add_discovery_links, priority=650)
    app.connect("env-purge-doc", remove_purged_markdown)
    app.connect("build-finished", export_documentation, priority=950)
