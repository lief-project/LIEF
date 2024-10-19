import lief
import sphinx_lief

from sphinx.application import Sphinx

def minify_option() -> dict[str, bool]:
    return {
        "html_minify": True,
        "css_minify": True,
        "html_prettify": False,
    }
    #return {
    #    "html_minify": False,
    #    "css_minify": False,
    #    "html_prettify": False,
    #}


def setup(app: Sphinx):
    app.config.html_theme_path       = sphinx_lief.html_theme_path()
    app.config.html_context          = sphinx_lief.get_html_context()
    app.config.html_theme            = app.config.lief_html_theme
    app.config.html_base_url         = app.config.lief_public_website
    app.config.base_url              = f"{app.config.html_base_url}/doc/{app.config.lief_doc_endpoint}"
    app.config.html_last_updated_fmt = '%d/%m/%Y, %H:%M:%S'
    app.config.html_logo             = '_static/logo_blue.png'
    app.config.html_favicon          = '_static/favicon.ico'
    app.config.html_static_path      = ['_static']
    app.config.htmlhelp_basename     = 'LIEFdoc'
    app.config.html_theme_options = {
        "commit": app.config.lief_commit,
        "base_url": f"{app.config.base_url}/",
        "sponsor_link": app.config.lief_gh_sponsor_url,
        "discord_invite": app.config.lief_discord,
        "repo_url": app.config.lief_gh_repo_url,
        "repo_name": app.config.lief_gh_repo,
        "logo_icon": "logo_blue.png",
        "globaltoc_depth": 2,
        "color_primary": "blue",
        "color_accent": "cyan",
        "touch_icon": "favicon.ico",
        "nav_links": [
            {
                "href": app.config.html_base_url,
                "internal": False,
                "title": "Home",
                "icon": "fa-solid fa-house"
            },
            {
                "href": f"{app.config.html_base_url}/blog",
                "internal": False,
                "title": "Blog",
                "icon": "fa-solid fa-rss"
            },
            {
                "href": f"{app.config.html_base_url}/download",
                "internal": False,
                "title": "Download",
                "icon": "fa-solid fa-download",
            },
            {
                "href": "index",
                "internal": True,
                "title": "Documentation",
                "icon": "fa-solid fa-book",
                "subnav": [
                    {
                        "title": "Doxygen",
                        "href": f"{app.config.base_url}/doxygen",
                    },
                ]
            },
            {
                "href": f"{app.config.html_base_url}/about",
                "internal": False,
                "title": "About",
                "icon": "fa-solid fa-bars-staggered"
            },
        ],
        "table_classes": ["plain"],
    }

    app.config.html_theme_options.update(minify_option())
