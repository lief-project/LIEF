from __future__ import annotations

import json
import re
from html import unescape
from pathlib import Path
from typing import Any
from urllib.parse import urljoin
from xml.etree import ElementTree

from docutils import nodes
from sphinx.application import Sphinx
from sphinx.environment import BuildEnvironment
from sphinx.errors import ExtensionError
from sphinx_lief_doc.lief_api import liefapi_elements

MAX_DESCRIPTION_LENGTH = 160
MIN_DESCRIPTION_LENGTH = 50
ROOT_DESCRIPTION = (
    "LIEF documentation for parsing, inspecting, modifying, and writing ELF, "
    "PE, Mach-O, COFF, Android, and other executable formats in C++, Python, "
    "and Rust."
)
ROOT_TITLE = "LIEF Documentation - ELF, PE, Mach-O and Binary Analysis"
SOCIAL_IMAGE = "_static/lief-social.webp"

_HTML_TAG = re.compile(r"<[^>]+>")
_LANGUAGE_TITLES = {"C++", "Python", "Rust"}
_UNHELPFUL_LEADS = (
    "please check:",
    "you can also find the doxygen documentation",
)


def _plain_text(value: object) -> str:
    text = unescape(_HTML_TAG.sub(" ", str(value or "")))
    return " ".join(text.replace("¶", " ").split())


def _truncate(value: str, limit: int = MAX_DESCRIPTION_LENGTH) -> str:
    text = _plain_text(value)
    if len(text) <= limit:
        return text
    shortened = text[: limit - 1].rsplit(" ", 1)[0].rstrip(" ,;:-")
    return f"{shortened}…"


def _parent_titles(context: dict[str, Any]) -> list[str]:
    titles = []
    for parent in context.get("parents", ()):
        title = _plain_text(parent.get("title", ""))
        if title:
            titles.append(title)
    return titles


def _paragraph_text(paragraph: nodes.paragraph) -> str:
    parts = []

    def collect(node: nodes.Node) -> None:
        if isinstance(node, liefapi_elements):
            return
        if isinstance(node, nodes.Text):
            parts.append(str(node))
            return
        for child in node.children:
            collect(child)

    collect(paragraph)
    return _plain_text("".join(parts))


def _page_subject(context: dict[str, Any]) -> str:
    title = _plain_text(context.get("title", ""))
    parents = _parent_titles(context)
    parent = parents[-1] if parents else ""

    if title in _LANGUAGE_TITLES and parent:
        return f"{parent} {title} API"
    if parent in _LANGUAGE_TITLES and len(parents) > 1:
        return f"{title} {parent} {parents[-2]}"
    if parent and parent.casefold() not in title.casefold():
        return f"{title} in {parent}"
    return title


def _page_title(app: Sphinx, pagename: str, context: dict[str, Any]) -> str:
    if pagename == app.config.root_doc:
        return ROOT_TITLE
    if pagename == "genindex":
        return "LIEF API Index - LIEF Documentation"

    title = _plain_text(context.get("title", pagename))
    parents = _parent_titles(context)
    parent = parents[-1] if parents else ""

    if title in _LANGUAGE_TITLES and parent:
        subject = f"{parent} {title} API"
    elif parent in _LANGUAGE_TITLES and len(parents) > 1:
        subject = f"{title} - {parent} {parents[-2]}"
    elif parent and parent.casefold() not in title.casefold():
        subject = f"{title} - {parent}"
    else:
        subject = title

    return f"{subject} - LIEF Documentation"


def _lead_paragraph(app: Sphinx, pagename: str) -> str:
    if pagename not in app.env.found_docs:
        return ""

    doctree = app.env.get_doctree(pagename)
    for paragraph in doctree.findall(nodes.paragraph):
        ancestor = paragraph.parent
        while ancestor is not None and isinstance(
            ancestor, (nodes.document, nodes.section)
        ):
            ancestor = ancestor.parent
        if ancestor is not None:
            continue

        candidate = _paragraph_text(paragraph)
        if len(candidate) < 24:
            continue
        if candidate.casefold().startswith(_UNHELPFUL_LEADS):
            continue
        return candidate
    return ""


def _page_description(app: Sphinx, pagename: str, context: dict[str, Any]) -> str:
    if context.get("seo_description_in_metatags"):
        return _truncate(context.get("seo_description", ""))
    authored_description = app.env.metadata.get(pagename, {}).get("description", "")
    if authored_description:
        return _truncate(authored_description)
    if pagename == app.config.root_doc:
        return ROOT_DESCRIPTION
    if pagename == "genindex":
        return (
            "Alphabetical index of LIEF C++, Python, and Rust APIs for parsing, "
            "inspecting, modifying, and writing executable formats."
        )

    subject = _page_subject(context)
    paragraph = _lead_paragraph(app, pagename)
    if paragraph:
        description = paragraph
        if subject and subject.casefold() not in paragraph.casefold():
            description = f"{subject}. {paragraph}"
        description = _truncate(description)
        if len(description) >= MIN_DESCRIPTION_LENGTH:
            return description

    return _truncate(
        f"{subject} reference documentation for LIEF, including APIs and "
        "examples for parsing, inspecting, modifying, and writing executable "
        "formats."
    )


def _page_url(app: Sphinx, pagename: str) -> str:
    base_url = app.config.html_theme_options.get("base_url", "")
    if not base_url:
        return ""
    target = app.builder.get_target_uri(pagename).lstrip("/")
    return f"{base_url.rstrip('/')}/{target}"


def _breadcrumb_json(
    app: Sphinx,
    pagename: str,
    context: dict[str, Any],
    canonical_url: str,
) -> str:
    if pagename == app.config.root_doc or not canonical_url:
        return ""

    root_url = _page_url(app, app.config.root_doc)
    items = [("Docs", root_url)]
    for parent in context.get("parents", ()):
        name = _plain_text(parent.get("title", ""))
        link = parent.get("link", "")
        if name and link:
            items.append((name, urljoin(canonical_url, link)))
    items.append((_plain_text(context.get("title", "")), canonical_url))

    unique_items = []
    seen_urls = set()
    for name, url in items:
        if not name or not url or url in seen_urls:
            continue
        seen_urls.add(url)
        unique_items.append((name, url))

    if len(unique_items) < 2:
        return ""

    payload = {
        "@context": "https://schema.org",
        "@type": "BreadcrumbList",
        "itemListElement": [
            {
                "@type": "ListItem",
                "position": position,
                "name": name,
                "item": url,
            }
            for position, (name, url) in enumerate(unique_items, start=1)
        ],
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).replace(
        "<", "\\u003c"
    )


def add_seo_context(
    app: Sphinx,
    pagename: str,
    templatename: str,
    context: dict[str, Any],
    doctree: nodes.document | None,
) -> None:
    del templatename, doctree

    context["seo_title"] = _page_title(app, pagename, context)
    context["seo_description"] = _page_description(app, pagename, context)

    if pagename == "genindex":
        context["seo_noindex"] = True

    if pagename in {"genindex", "search"}:
        return

    canonical_url = context.get("canonical_url") or context.get("pageurl")
    if not canonical_url:
        canonical_url = _page_url(app, pagename)
    context["canonical_url"] = canonical_url

    base_url = app.config.html_theme_options.get("base_url", "")
    context["seo_image_url"] = f"{base_url.rstrip('/')}/{SOCIAL_IMAGE}"
    context["seo_breadcrumb_json"] = _breadcrumb_json(
        app, pagename, context, canonical_url
    )


def remove_stale_helpers(app: Sphinx) -> None:
    if app.builder.name == "html":
        (Path(app.outdir) / "_cross_api.html").unlink(missing_ok=True)


def remove_purged_page(app: Sphinx, env: BuildEnvironment, docname: str) -> None:
    """Keep incremental output free of HTML for removed or renamed sources."""
    del env
    if app.builder.name != "html":
        return

    output = Path(app.outdir).resolve()
    page = Path(app.builder.get_outfilename(docname)).resolve()
    if page.suffix == ".html" and page.is_relative_to(output):
        page.unlink(missing_ok=True)


class _MetadataParser:
    def __init__(self, path: Path) -> None:
        from bs4 import BeautifulSoup

        self.soup = BeautifulSoup(path.read_text(encoding="utf-8"), "html.parser")

    def title(self) -> str:
        return _plain_text(self.soup.title.string if self.soup.title else "")

    def meta(self, *, name: str = "", prop: str = "") -> list[str]:
        attrs = {"name": name} if name else {"property": prop}
        return [
            tag.get("content", "").strip() for tag in self.soup.find_all("meta", attrs)
        ]

    def links(self, relation: str) -> list[str]:
        return [
            tag.get("href", "").strip()
            for tag in self.soup.find_all("link", rel=relation)
        ]

    def json_ld(self) -> list[dict[str, Any]]:
        payloads = []
        for script in self.soup.find_all("script", type="application/ld+json"):
            payloads.append(json.loads(script.string or "{}"))
        return payloads


def validate_seo(app: Sphinx, exception: Exception | None) -> None:
    if exception is not None or app.builder.name != "html":
        return

    output = Path(app.outdir)
    errors = []
    seen_titles: dict[str, str] = {}
    seen_descriptions: dict[str, str] = {}
    seen_canonicals: dict[str, str] = {}

    if (output / "_cross_api.html").exists():
        errors.append("internal helper _cross_api.html must not be generated")

    for path in sorted(output.rglob("*.html")):
        if ".doctrees" in path.parts:
            continue
        relative = path.relative_to(output).as_posix()
        metadata = _MetadataParser(path)
        title = metadata.title()
        descriptions = metadata.meta(name="description")
        robots = ",".join(metadata.meta(name="robots")).casefold()
        noindex = "noindex" in robots

        title_key = title.casefold()
        if not title:
            errors.append(f"{relative}: missing title")
        elif not noindex:
            if title_key in seen_titles:
                errors.append(
                    f"{relative}: duplicate title also used by {seen_titles[title_key]}"
                )
            else:
                seen_titles[title_key] = relative

        if len(descriptions) != 1:
            errors.append(
                f"{relative}: expected one meta description, found {len(descriptions)}"
            )
        elif not noindex and not (
            MIN_DESCRIPTION_LENGTH <= len(descriptions[0]) <= MAX_DESCRIPTION_LENGTH
        ):
            errors.append(
                f"{relative}: meta description length is {len(descriptions[0])}"
            )
        elif not noindex:
            description_key = descriptions[0].casefold()
            if description_key in seen_descriptions:
                errors.append(
                    f"{relative}: duplicate description also used by "
                    f"{seen_descriptions[description_key]}"
                )
            else:
                seen_descriptions[description_key] = relative

        missing_alt = [
            img for img in metadata.soup.find_all("img") if not img.has_attr("alt")
        ]
        if missing_alt:
            errors.append(f"{relative}: {len(missing_alt)} image(s) missing alt")

        if noindex:
            continue

        if metadata.soup.find("h1") is None:
            errors.append(f"{relative}: missing a level-one heading")

        canonicals = metadata.links("canonical")
        if len(canonicals) != 1 or not canonicals[0].startswith("https://"):
            errors.append(f"{relative}: expected one absolute HTTPS canonical URL")
        elif canonicals[0] in seen_canonicals:
            errors.append(
                f"{relative}: duplicate canonical also used by "
                f"{seen_canonicals[canonicals[0]]}"
            )
        else:
            seen_canonicals[canonicals[0]] = relative

        social_properties = {}
        for prop in ("og:title", "og:description", "og:type", "og:url", "og:image"):
            social_properties[prop] = metadata.meta(prop=prop)
            if len(metadata.meta(prop=prop)) != 1:
                errors.append(f"{relative}: expected one {prop} property")
        twitter_properties = {}
        for name in (
            "twitter:card",
            "twitter:title",
            "twitter:description",
            "twitter:image",
        ):
            twitter_properties[name] = metadata.meta(name=name)
            if len(twitter_properties[name]) != 1:
                errors.append(f"{relative}: expected one {name} property")

        if social_properties["og:title"] != [title]:
            errors.append(f"{relative}: og:title does not match the page title")
        if descriptions and social_properties["og:description"] != descriptions:
            errors.append(
                f"{relative}: og:description does not match the meta description"
            )
        if canonicals and social_properties["og:url"] != canonicals:
            errors.append(f"{relative}: og:url does not match the canonical URL")
        if social_properties["og:image"] and not social_properties["og:image"][
            0
        ].startswith("https://"):
            errors.append(f"{relative}: og:image must use an absolute HTTPS URL")
        if twitter_properties["twitter:card"] != ["summary"]:
            errors.append(f"{relative}: twitter:card must be summary")
        if twitter_properties["twitter:title"] != [title]:
            errors.append(f"{relative}: twitter:title does not match the page title")
        if descriptions and twitter_properties["twitter:description"] != descriptions:
            errors.append(
                f"{relative}: twitter:description does not match the meta description"
            )
        if (
            social_properties["og:image"]
            and twitter_properties["twitter:image"] != social_properties["og:image"]
        ):
            errors.append(f"{relative}: twitter:image does not match og:image")

        if relative != "index.html":
            try:
                breadcrumbs = [
                    item
                    for item in metadata.json_ld()
                    if item.get("@type") == "BreadcrumbList"
                ]
            except (json.JSONDecodeError, AttributeError) as error:
                errors.append(f"{relative}: invalid JSON-LD: {error}")
            else:
                if len(breadcrumbs) != 1:
                    errors.append(
                        f"{relative}: expected one BreadcrumbList JSON-LD object"
                    )
                else:
                    breadcrumb_items = breadcrumbs[0].get("itemListElement", ())
                    if len(breadcrumb_items) < 2:
                        errors.append(
                            f"{relative}: breadcrumb JSON-LD needs at least two items"
                        )
                    elif [item.get("position") for item in breadcrumb_items] != list(
                        range(1, len(breadcrumb_items) + 1)
                    ):
                        errors.append(
                            f"{relative}: breadcrumb positions must be consecutive"
                        )
                    elif not all(
                        item.get("name")
                        and str(item.get("item", "")).startswith("https://")
                        for item in breadcrumb_items
                    ):
                        errors.append(
                            f"{relative}: breadcrumb names and HTTPS URLs are required"
                        )
                    elif (
                        canonicals and breadcrumb_items[-1].get("item") != canonicals[0]
                    ):
                        errors.append(
                            f"{relative}: final breadcrumb must match the canonical URL"
                        )

    sitemap = output / "sitemap.xml"
    if not sitemap.exists():
        errors.append("sitemap.xml was not generated")
    else:
        root = ElementTree.parse(sitemap).getroot()
        namespace = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        locations = [node.text or "" for node in root.findall("s:url/s:loc", namespace)]
        if len(locations) != len(set(locations)):
            errors.append("sitemap.xml contains duplicate URLs")
        if any(url.endswith("/_cross_api.html") for url in locations):
            errors.append("sitemap.xml contains the internal cross API helper")
        expected_locations = set(seen_canonicals)
        if set(locations) != expected_locations:
            missing = expected_locations - set(locations)
            unexpected = set(locations) - expected_locations
            errors.append(
                "sitemap.xml does not match the indexable HTML pages; "
                f"missing={sorted(missing)}, unexpected={sorted(unexpected)}"
            )

    if errors:
        details = "\n".join(f"- {error}" for error in errors)
        raise ExtensionError(f"SEO validation failed:\n{details}")


def setup(app: Sphinx) -> None:
    app.connect("builder-inited", remove_stale_helpers)
    app.connect("env-purge-doc", remove_purged_page)
    app.connect("html-page-context", add_seo_context, priority=600)
    app.connect("build-finished", validate_seo, priority=900)
