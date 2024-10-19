from docutils import nodes
from docutils.nodes import raw

from collections.abc import Sequence  # NoQA: TCH003

from docutils.parsers.rst.states import Inliner  # NoQA: TCH002

from sphinx.environment import BuildEnvironment
from sphinx.config import Config
from sphinx.application import Sphinx

def _get_env(inliner: Inliner) -> BuildEnvironment:
    return inliner.document.settings.env

def _get_config(inliner) -> Config:
    return _get_env(inliner).config

def _github_prefix(config: Config):
    return f"https://github.com/{config.lief_gh_org}/{config.lief_gh_repo}"

def issue_role(name: str, rawtext: str, text: str, lineno: int,
               inliner: Inliner, options: dict | None = None, content: Sequence[str] = ()):

    config = _get_config(inliner)
    return [
        nodes.reference("", '#' + text,
                        refuri=f"{_github_prefix(config)}/issues/{text}",
                        **options or {})
    ], []

def commit_role(name: str, rawtext: str, text: str, lineno: int,
                inliner: Inliner, options: dict | None = None, content: Sequence[str] = ()):
    config = _get_config(inliner)
    return [
        nodes.reference("", text[:7],
                        refuri=f"{_github_prefix(config)}/commit/{text}",
                        **options or {})
    ], []

def pr_role(name: str, rawtext: str, text: str, lineno: int,
            inliner: Inliner, options: dict | None = None, content: Sequence[str] = ()):
    config = _get_config(inliner)
    return [
        nodes.reference("", '#' + text,
                        refuri=f"{_github_prefix(config)}/pull/{text}")
    ], []

def github_user(name: str, rawtext: str, text: str, lineno: int,
                inliner: Inliner, options: dict | None = None, content: Sequence[str] = ()):
    return [
        nodes.reference("", text, refuri=f"https://github.com/{text}",
                        **options or {})
    ], []

def xmark(name: str, rawtext: str, text: str, lineno: int,
          inliner: Inliner, options: dict | None = {}, content: Sequence[str] = ()):
    options["format"] = "html"
    node = raw(text='<b class="fa-solid fa-xmark text-danger me-1"></b>', **options)
    return [node], []

def fa_check(name: str, rawtext: str, text: str, lineno: int,
             inliner: Inliner, options: dict | None = {}, content: Sequence[str] = ()):
    options["format"] = "html"
    node = raw(text='<b class="fa-solid fa-check text-success me-1"></b>', **options)
    return [node], []

def setup(app: Sphinx):
    app.add_role('commit', commit_role)
    app.add_role('pr', pr_role)
    app.add_role('issue', issue_role)
    app.add_role('github_user', github_user)
    app.add_role('xmark', xmark)
    app.add_role('fa-check', fa_check)
