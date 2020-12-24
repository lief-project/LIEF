#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# LIEF documentation build configuration file

import lief
import os
import pathlib
from docutils import nodes

GENERATE_DOXYGEN = False
DOXYGEN_XML_PATH = None
USE_RTD_THEME = False

try:
    import sphinx_lief
except Exception:
    import sphinx_rtd_theme
    USE_RTD_THEME = True


try:
    import breathe
    DOXYGEN_XML_PATH = os.getenv("LIEF_DOXYGEN_XML", None)
    if DOXYGEN_XML_PATH is not None and pathlib.Path(DOXYGEN_XML_PATH).exists():
        DOXYGEN_XML_PATH = pathlib.Path(DOXYGEN_XML_PATH).resolve().absolute()
        GENERATE_DOXYGEN = True
except Exception:
    GENERATE_DOXYGEN = False


FORCE_RTD_THEME = os.environ.get("FORCE_RTD_THEME", False)
FORCE_RTD_THEME = FORCE_RTD_THEME in ("1", "true", "yes")

if FORCE_RTD_THEME:
    import sphinx_rtd_theme

USE_RTD_THEME = USE_RTD_THEME or FORCE_RTD_THEME

extensions = [
    'sphinx.ext.mathjax',
    'sphinx.ext.autodoc',
]

if GENERATE_DOXYGEN:
    extensions += ["breathe"]
    breathe_projects = {
        "lief": DOXYGEN_XML_PATH,
    }

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

source_suffix = '.rst'

master_doc = 'index'

project    = 'LIEF'
html_title = "LIEF Documentation"
copyright  = '2020, Quarkslab'
author     = 'Romain Thomas'

version = lief.__tag__ if lief.__is_tagged__ else lief.__version__
release = lief.__version__
commit  = lief.__commit__

language = "en"
autoclass_content = 'both'

if GENERATE_DOXYGEN:
    breathe_default_members = ('members', 'protected-members', 'undoc-members')
    breathe_show_enumvalue_initializer = True

exclude_patterns = []

# -- Options for HTML output ----------------------------------------------
def commit_role(name, rawtext, text, lineno, inliner, options={}, content=[]):
    commit_link = nodes.reference(
            "", text[:7], refuri="https://github.com/lief-project/LIEF/commit/{}".format(text), **options)

    return [commit_link], []


def pr_role(name, rawtext, text, lineno, inliner, options={}, content=[]):
    pr_link = nodes.reference(
            "", '#' + text, refuri="https://github.com/lief-project/LIEF/pull/{}".format(text), **options)

    return [pr_link], []


def issue_role(name, rawtext, text, lineno, inliner, options={}, content=[]):
    issue_link = nodes.reference(
            "", '#' + text, refuri="https://github.com/lief-project/LIEF/issues/{}".format(text), **options)

    return [issue_link], []

def github_user(name, rawtext, text, lineno, inliner, options={}, content=[]):
    issue_link = nodes.reference(
            "", text, refuri="https://github.com/{}".format(text), **options)

    return [issue_link], []

def setup(app):
    app.add_css_file('css/custom.css')  # may also be an URL

    app.add_role('commit', commit_role)
    app.add_role('pr', pr_role)
    app.add_role('issue', issue_role)
    app.add_role('github_user', github_user)

linkcheck_request_headers = {
    "*": {
        "Accept": "text/html,application/atom+xml",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0",
    }
}
linkcheck_workers = 1
linkcheck_ignore = [
    'https://github.com',
    'http://github.com',
]


if not USE_RTD_THEME:
    pygments_style = "xcode"
    endpoint = "stable" if lief.__is_tagged__ else "latest"
    extensions.append("sphinx_lief")
    html_theme_path = sphinx_lief.html_theme_path()
    html_context    = sphinx_lief.get_html_context()
    html_theme      = "sphinx_lief"
    html_base_url   = "https://lief-project.github.io/"
    base_url        = "{}/doc/{}".format(html_base_url, endpoint)
    html_theme_options = {
        "commit": commit,
        "base_url": "{}/".format(base_url),
        "repo_url": "https://github.com/lief-project/LIEF/",
        "repo_name": "LIEF",
        "html_minify": True,
        "html_prettify": False,
        "css_minify": True,
        "logo_icon": "logo_blue.png",
        "globaltoc_depth": 2,
        "color_primary": "blue",
        "color_accent": "cyan",
        "touch_icon": "favicon.ico",
        "nav_links": [
            {
                "href": html_base_url,
                "internal": False,
                "title": "Home"
            },
            {
                "href": "{}/blog".format(html_base_url),
                "internal": False,
                "title": "Blog"
            },
            {
                "href": "{}/download".format(html_base_url),
                "internal": False,
                "title": "Download"
            },
            {
                "href": "index",
                "internal": True,
                "title": "Documentation",
                "subnav": [
                    {
                        "title": "Doxygen",
                        "href": "{}/doxygen".format(base_url),
                    },
                ]
            },
            {
                "href": "{}/about".format(html_base_url),
                "internal": False,
                "title": "About",
            },
        ],
        "table_classes": ["plain"],
    }
else:
    html_theme = "sphinx_rtd_theme"
    html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]

html_last_updated_fmt = '%d/%m/%Y, %H:%M:%S'
html_logo        = '_static/logo_blue.png'
html_favicon     = '_static/favicon.ico'
html_static_path = ['_static']

htmlhelp_basename = 'LIEFdoc'

