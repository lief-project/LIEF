#!/usr/bin/env python3
import sys
import os
import re
import logging
import pathlib
import subprocess
import shutil
import json
import requests
import itertools
from collections import defaultdict
from datetime import datetime
from mako.template import Template
from enum import Enum, auto
import twine

from twine.settings import Settings as TwineSettings
from twine.commands import upload as twine_upload

class CI(Enum):
    UNKNOWN        = auto()
    TRAVIS         = auto()
    APPVEYOR       = auto()
    GITLAB_CI      = auto()
    CIRCLE_CI      = auto()
    GITHUB_ACTIONS = auto()
    AZURE          = auto()
    LOCAL          = auto()

def pretty_ci_name(ci):
    return str(ci).split(".")[-1].replace("_", "-").lower()

def is_pr(ci):
    if ci == CI.TRAVIS:
        cond1 = os.getenv("TRAVIS_EVENT_TYPE", "pull_request") == "pull_request"
        cond2 = not (os.getenv("TRAVIS_REPO_SLUG", "").startswith("lief-project/") or os.getenv("TRAVIS_REPO_SLUG", "").startswith("romainthomas/LIEF"))
        return cond1 or cond2
    elif ci == CI.APPVEYOR:
        logger.info("%s - %s", os.getenv("APPVEYOR_PULL_REQUEST_NUMBER", -1), os.getenv("APPVEYOR_REPO_NAME", ""))
        pr_number = os.getenv("APPVEYOR_PULL_REQUEST_NUMBER", "")
        cond1 = len(pr_number) != 0 and int(pr_number) >= 0
        cond2 = not (os.getenv("APPVEYOR_REPO_NAME", "").startswith("lief-project/") or os.getenv("APPVEYOR_REPO_NAME", "").startswith("romainthomas/"))
        return cond1 or cond2
    elif ci == CI.CIRCLE_CI:
        cond1 = int(os.getenv("CIRCLE_PR_NUMBER", -1)) >= 0
        cond2 = os.getenv("CIRCLE_PROJECT_USERNAME", "") != "lief-project" and os.getenv("CIRCLE_PROJECT_USERNAME", "") != "romainthomas"
        return cond1 or cond2
    elif ci == CI.GITHUB_ACTIONS:
        cond1 = os.getenv("GITHUB_HEAD_REF", "") != ""
        cond2 = not (os.getenv("GITHUB_REPOSITORY", "").startswith("lief-project/") or os.getenv("GITHUB_REPOSITORY", "").startswith("romainthomas/LIEF"))
        return cond1 or cond2
    elif ci == CI.LOCAL:
        return False
    return True

def get_branch(ci):
    if ci == CI.TRAVIS:
        return os.getenv("TRAVIS_BRANCH")
    elif ci == CI.APPVEYOR:
        return os.getenv("APPVEYOR_REPO_BRANCH")
    elif ci == CI.CIRCLE_CI:
        return os.getenv("CIRCLE_BRANCH")
    elif ci == CI.GITHUB_ACTIONS:
        return os.getenv("GITHUB_REF").replace("refs/heads/", "")
    elif ci == CI.LOCAL:
        return os.getenv("CI_BRANCH")
    return None

def get_ci_workdir(ci):
    if ci == CI.CIRCLE_CI:
        return os.getenv("CIRCLE_WORKING_DIRECTORY")
    elif ci == CI.TRAVIS:
        return os.getenv("TRAVIS_BUILD_DIR")
    elif ci == CI.APPVEYOR:
        return  os.getenv("APPVEYOR_BUILD_FOLDER")
    elif ci == CI.GITHUB_ACTIONS:
        return os.getenv("GITHUB_WORKSPACE")
    elif ci == CI.LOCAL:
        return os.getenv("CI_WORKING_DIR")
    else:
        logger.critical("Unsupported CI to resolve working directory")
        sys.exit(1)

def get_tag(ci):
    if ci == CI.CIRCLE_CI:
        return os.getenv("CIRCLE_TAG", "")
    elif ci == CI.TRAVIS:
        return os.getenv("TRAVIS_TAG", "")
    elif ci == CI.APPVEYOR:
        if "APPVEYOR_REPO_TAG_NAME" in os.environ:
            return os.getenv("APPVEYOR_REPO_TAG_NAME", "")
        return ""
    elif ci == CI.GITHUB_ACTIONS:
        ref = os.getenv("GITHUB_REF", "")
        logger.info("Github Action tag: {}".format(ref))
        if ref.startswith("refs/tags/"):
            return ref.replace("refs/tags/", "")
        return ""
    elif ci == CI.LOCAL:
        return os.getenv("CI_TAG")
    else:
        logger.critical("Unsupported CI to resolve working directory")
        sys.exit(1)

LOG_LEVEL = logging.DEBUG

logging.getLogger().addHandler(logging.StreamHandler(stream=sys.stdout))
logging.getLogger().setLevel(LOG_LEVEL)
logger = logging.getLogger(__name__)

CURRENT_CI = CI.UNKNOWN

# Detect CI
# ===========================================
if os.getenv("TRAVIS", None) is not None:
    CURRENT_CI = CI.TRAVIS
elif os.getenv("APPVEYOR", None) is not None:
    CURRENT_CI = CI.APPVEYOR
elif os.getenv("GITHUB_ACTIONS", None) is not None:
    CURRENT_CI = CI.GITHUB_ACTIONS
elif os.getenv("GITLAB_CI", None) is not None:
    CURRENT_CI = CI.GITLAB_CI
elif os.getenv("CI_LOCAL", "") == "true":
    CURRENT_CI = CI.LOCAL
else:
    logger.error("Can't detect CI!")
    sys.exit(1)

CI_PRETTY_NAME = pretty_ci_name(CURRENT_CI)
logger.info("CI: %s", CI_PRETTY_NAME)

ALLOWED_BRANCHES = {"master", "deploy", "devel", "feat/gitlab-packages"}
BRANCH_NAME = get_branch(CURRENT_CI)
TAG_NAME    = get_tag(CURRENT_CI)
IS_TAGGED   = TAG_NAME is not None and len(TAG_NAME) > 0

logger.info("Branch: %s", BRANCH_NAME)
logger.info("Tag:    %s", TAG_NAME)

if BRANCH_NAME not in ALLOWED_BRANCHES and not IS_TAGGED:
    logger.info("Skip deployment for branch '%s'", BRANCH_NAME)
    sys.exit(0)

if is_pr(CURRENT_CI):
    logger.info("Skip pull request")
    sys.exit(0)

CURRENTDIR = pathlib.Path(__file__).resolve().parent
REPODIR    = CURRENTDIR.parent

LIEF_GITLAB_TOKEN = os.getenv("LIEF_GITLAB_TOKEN", None)
DEPLOY_KEY        = os.getenv("LIEF_AUTOMATIC_BUILDS_KEY", None)
DEPLOY_IV         = os.getenv("LIEF_AUTOMATIC_BUILDS_IV", None)

if DEPLOY_KEY is None or len(DEPLOY_KEY) == 0:
    logger.error("Deploy key is not set!")
    sys.exit(1)

if DEPLOY_IV is None or len(DEPLOY_IV) == 0:
    logger.error("Deploy IV is not set!")
    sys.exit(1)

if LIEF_GITLAB_TOKEN is None or len(LIEF_GITLAB_TOKEN) == 0:
    logger.error("LIEF_GITLAB_TOKEN is not set!")
    sys.exit(1)

GIT_USER  = "lief-{}-ci".format(CI_PRETTY_NAME)
GIT_EMAIL = "ci@lief.re"

CI_CWD = pathlib.Path(get_ci_workdir(CURRENT_CI))

if CI_CWD is None:
    logger.debug("Can't resolve CI working dir")
    sys.exit(1)

LIEF_PACKAGE_REPO     = "https://github.com/lief-project/packages.git"
LIEF_PACKAGE_DIR      = REPODIR / "deploy-packages"
LIEF_PACKAGE_SSH_REPO = "git@github.com:lief-project/packages.git"
SDK_PACKAGE_DIR       = LIEF_PACKAGE_DIR / "sdk"
PYPI_PACKAGE_DIR      = LIEF_PACKAGE_DIR / "lief"
DIST_DIR              = REPODIR / "dist"
BUILD_DIR             = REPODIR / "build"

# Gitlab
GITLAB_PROJECT_ID = int(os.getenv("GITLAB_PROJECT_ID", 0)) # https://gitlab.com/lief-project/packages

if GITLAB_PROJECT_ID == 0:
    logger.error("GITLAB_PROJECT_ID is not set!")
    sys.exit(1)

logger.debug("Working directory: %s", CI_CWD)

SSH_DIR     = pathlib.Path("~/.ssh").expanduser().resolve()
PYTHON      = shutil.which("python")
GIT         = shutil.which("git")
TAR         = shutil.which("tar")
OPENSSL     = shutil.which("openssl")
MV          = shutil.which("mv")
RM          = shutil.which("rm")
SSH_AGENT   = shutil.which("ssh-agent")
SSH_ADD     = shutil.which("ssh-add")
SSH_KEYSCAN = shutil.which("ssh-keyscan")

INDEX_TEMPLATE = r"""
<html>
<title>Links for lief</title>
<body>
<h1>Links for lief</h1>
% for name, file_id in files:
    <a href="https://gitlab.com/lief-project/packages/-/package_files/${file_id}/download">${name}</a><br />
% endfor
</body>
</html>
"""

class NotFound(Exception):
    pass

def delete_package(info):
    logger.info("Deleting %s [%s] (%s)", info["package_type"], info["name"], info["version"])
    url = "https://gitlab.com/api/v4/projects/{project_id}/packages/{id}"
    headers = {
        "PRIVATE-TOKEN": LIEF_GITLAB_TOKEN
    }

    url = url.format(
        project_id=GITLAB_PROJECT_ID,
        id=info["id"],
    )
    r = requests.delete(url, headers=headers)

    if r.status_code != 204:
        logger.error("Error while deleting the package (%s)", r.text)
        raise NotFound


def delete_file(file_info):
    logger.info("Deleting %s [%s]", file_info["file_name"], file_info["created_at"])
    url = "https://gitlab.com/api/v4/projects/{project_id}/packages/{pkd_id}/package_files/{file_id}"
    headers = {
        "PRIVATE-TOKEN": LIEF_GITLAB_TOKEN
    }

    url = url.format(
        project_id=GITLAB_PROJECT_ID,
        pkd_id=file_info["package_id"],
        file_id=file_info["id"],
    )
    r = requests.delete(url, headers=headers)
    if r.status_code != 204:
        logger.error("Error while deleting the file (%s)", r.text)
        sys.exit(1)

def list_packages_files(pkg_id: int):
    url = "https://gitlab.com/api/v4/projects/{project_id}/packages/{pkg_id}/package_files"
    url = url.format(project_id=GITLAB_PROJECT_ID, pkg_id=pkg_id)

    headers = {
        "PRIVATE-TOKEN": LIEF_GITLAB_TOKEN
    }

    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        logger.error("Error while listing packages with id: %d (%s)", pkg_id, r.text)
        sys.exit(1)

    return r.json()

def list_packages():
    url     = "https://gitlab.com/api/v4/projects/{project_id}/packages".format(project_id=GITLAB_PROJECT_ID)
    headers = {
        "PRIVATE-TOKEN": LIEF_GITLAB_TOKEN
    }

    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        logger.error("Error while trying to list packages (%s)", r.text)
        sys.exit(1)

    return r.json()

def push_file(file_path: str, pkg_name: str, version: str):
    file = pathlib.Path(file_path)
    if not file.exists():
        logger.error("%s does not exist", file_path)
        return None

    url     = "https://gitlab.com/api/v4/projects/{project_id}/packages/generic/{pkg_name}/{version}/{file_name}"
    headers = {
        "PRIVATE-TOKEN": LIEF_GITLAB_TOKEN
    }

    url = url.format(
        project_id=GITLAB_PROJECT_ID,
        pkg_name=pkg_name,
        version=version,
        file_name=file.name
    )

    r = requests.put(url, data=file.read_bytes(), headers=headers)
    if r.status_code != 201:
        logger.error("Error while trying to upload: %s (%s)", file_path, r.text)
        sys.exit(1)

    return r.json()

def is_pypi(info) -> bool:
    return info["package_type"] == "pypi"

def is_generic(info) -> bool:
    return info["package_type"] == "generic"

def delete_pypi():
    for pkg in filter(is_pypi, list_packages()):
        try:
            delete_package(pkg)
        except NotFound:
            continue

def pypi_packages_to_remove():
    pypi_packages = [p for p in list_packages() if is_pypi(p)]
    sorted(pypi_packages, key=lambda e: e["created_at"])
    pypi_packages.reverse()
    if len(pypi_packages) <= 1:
        return []
    return pypi_packages[1:]

def push_wheel(file_path: str, try_count: int = 3):
    if try_count <= 0:
        sys.exit(1)

    url = "https://gitlab.com/api/v4/projects/{project_id}/packages/pypi"
    url = url.format(project_id=GITLAB_PROJECT_ID)

    settings: TwineSettings = TwineSettings(
        username="romainthomas",
        password=LIEF_GITLAB_TOKEN,
        repository_url=url,
        verbose=0
    )
    try:
        twine_upload.upload(settings, [file_path])
    except requests.exceptions.HTTPError as e:
        logger.error("%s", e)
        if e.response.status_code == 400:
            logger.error("-> %s", e.response.text)
            json_info = e.response.json()
            if json_info.get("message", "") == "Validation failed: File name has already been taken":
                return
        return push_wheel(file_path, try_count - 1)
    logger.info("%s uploaded!", file_path)


def process_pkg_files(files):
    targets     = []
    remove_list = []
    for fname, info in files.items():
        sorted(info, key=lambda e: e["created_at"])
        info.reverse()
        if len(info) == 0:
            pass
        elif len(info) == 1:
            targets.append(info[0])
        else:
            target    = info[0]
            to_remove = info[1:]
            targets.append(target)
            remove_list += to_remove
    return (tuple(targets), tuple(remove_list))

def process_packages():
    packages = list_packages()
    if packages is None:
        logger.error("No packages")
        sys.exit(1)

    keeps   = []
    removes = []

    for pkg in filter(is_generic, packages):
        name         = pkg["name"]
        version      = pkg["version"]
        package_type = pkg["package_type"]
        id           = pkg["id"]
        files = list_packages_files(id)
        files_info = defaultdict(list)
        for pkg_file in files:
            fname = pkg_file["file_name"]
            fdate = pkg_file["created_at"]
            files_info[fname].append(dict(pkg_file))
        keep, remove = process_pkg_files(files_info)

        keeps   += list(keep)
        removes += list(remove)

    return (keeps, removes)


def generate_wheel_index(files):
    tmpl_info = [(info["file_name"], info["id"]) for info in files]
    html = Template(INDEX_TEMPLATE).render(files=tmpl_info)
    return html

def generate_sdk_index(files):
    tmpl_info = [(info["file_name"], info["id"]) for info in files]
    html = Template(INDEX_TEMPLATE).render(files=tmpl_info)
    return html

def generate_index(files):
    python_wheels = [f for f in files if f["file_name"].endswith(".whl")]
    sdk_files     = [f for f in files if f["file_name"].endswith(".zip") or f["file_name"].endswith(".tar.gz")]

    wheel_index = generate_wheel_index(python_wheels)
    sdk_index = generate_sdk_index(sdk_files)

    SDK_PACKAGE_DIR.mkdir(exist_ok=True)
    PYPI_PACKAGE_DIR.mkdir(exist_ok=True)

    with open((PYPI_PACKAGE_DIR / "index.html").as_posix(), "w") as f:
        f.write(wheel_index)

    with open((SDK_PACKAGE_DIR / "index.html").as_posix(), "w") as f:
        f.write(sdk_index)

gitlab_packages_name    = "lief"
gitlab_packages_version = "latest"

if BRANCH_NAME != "master":
    gitlab_packages_name = "lief-{}".format(BRANCH_NAME.replace("/", "-").replace("_", "-"))

if IS_TAGGED:
    gitlab_packages_name    = "lief-{}".format(str(TAG_NAME))
    gitlab_packages_version = str(TAG_NAME)

for file in DIST_DIR.glob("*.whl"):
    logger.debug("[WHEEL] Uploading '%s'", file.as_posix())
    push_wheel(file.as_posix())
    #push_file(file.as_posix(), gitlab_packages_name, gitlab_packages_version)

for file in itertools.chain(BUILD_DIR.glob("*.zip"), BUILD_DIR.glob("*.tar.gz")):
    logger.debug("[SDK  ] Uploading '%s'", file.as_posix())
    push_file(file.as_posix(), gitlab_packages_name, gitlab_packages_version)


keep, remove = process_packages()

while len(remove) > 0:
    for file in remove:
        fname = file["file_name"]
        fdate = file["created_at"]
        logger.info("  [REMOVE]: %s (%s)", fname, fdate)
        delete_file(file)
    keep, remove = process_packages()


for file in keep:
    fname = file["file_name"]
    fdate = file["created_at"]
    logger.info("  [KEEP  ]: %s (%s)", fname, fdate)

for pkg in pypi_packages_to_remove():
    delete_package(pkg)

#####################
# Clone package repo
#####################
target_branch = "gh-pages"

if BRANCH_NAME != "master":
    target_branch = "packages-{}".format(BRANCH_NAME.replace("/", "-").replace("_", "-"))

if IS_TAGGED:
    target_branch = str(TAG_NAME)

new_branch = False
if not LIEF_PACKAGE_DIR.is_dir():
    cmd = "{} clone --branch={} -j8 --single-branch {} {}".format(GIT, target_branch, LIEF_PACKAGE_REPO, LIEF_PACKAGE_DIR)
    p = subprocess.Popen(cmd, shell=True, cwd=REPODIR, stderr=subprocess.STDOUT)
    p.wait()

    if p.returncode:
        cmd = "{} clone --branch=master -j8 --single-branch {} {}".format(GIT, LIEF_PACKAGE_REPO, LIEF_PACKAGE_DIR)
        pmaster = subprocess.Popen(cmd, shell=True, cwd=REPODIR, stderr=subprocess.STDOUT)
        pmaster.wait()
        if pmaster.returncode:
            sys.exit(1)
        new_branch = True

        cmd = "{} checkout --orphan {}".format(GIT, target_branch)
        pmaster = subprocess.Popen(cmd, shell=True, cwd=LIEF_PACKAGE_DIR, stderr=subprocess.STDOUT)
        pmaster.wait()
        if pmaster.returncode:
            sys.exit(1)

        cmd = "{} reset --hard".format(GIT)
        pmaster = subprocess.Popen(cmd, shell=True, cwd=LIEF_PACKAGE_DIR, stderr=subprocess.STDOUT)
        pmaster.wait()

(LIEF_PACKAGE_DIR / ".nojekyll").touch()

logger.info("CI: %s - %s", GIT_USER, GIT_EMAIL)
cmds = [
    "{} config user.name '{}'".format(GIT, GIT_USER),
    "{} config user.email '{}'".format(GIT, GIT_EMAIL),
    "{} reset --soft root".format(GIT),
    "{} ls-files -v".format(GIT),
]

for cmd in cmds:
    p = subprocess.Popen(cmd, shell=True, cwd=LIEF_PACKAGE_DIR, stderr=subprocess.STDOUT)
    p.wait()

    if p.returncode:
        sys.exit(1)

# Generate indexes for the wheels / SDK
generate_index(keep)

if not SSH_DIR.is_dir():
    SSH_DIR.mkdir(mode=0o700)

#fix_ssh_perms()
deploy_key_path = (REPODIR / ".github" / "deploy-key.enc").as_posix()
output_key_path = (REPODIR / ".git" / "deploy-key")
cmd = "{} aes-256-cbc -K {} -iv {} -in {} -out {} -d".format(
        OPENSSL, DEPLOY_KEY, DEPLOY_IV, deploy_key_path, output_key_path.as_posix())

kwargs = {
    'shell': True,
    'cwd':   REPODIR,
    'stdout': subprocess.DEVNULL,
    'stderr': subprocess.DEVNULL,
}

p = subprocess.Popen(cmd, **kwargs)
p.wait()

if p.returncode:
    sys.exit(1)

output_key_path.chmod(0o600)
logger.info(output_key_path)

process = subprocess.run(SSH_AGENT, stdout=subprocess.PIPE, universal_newlines=True, stderr=subprocess.STDOUT)
OUTPUT_PATTERN = re.compile(r'SSH_AUTH_SOCK=(?P<socket>[^;]+).*SSH_AGENT_PID=(?P<pid>\d+)', re.MULTILINE | re.DOTALL)
match = OUTPUT_PATTERN.search(process.stdout)
if match is None:
    logger.error("Can't start ssh-agent")
    sys.exit(1)

agent_data = match.groupdict()
logger.info(f'ssh agent data: {agent_data!s}')
logger.info('Exporting ssh agent environment variables' )

os.environ['SSH_AUTH_SOCK'] = agent_data['socket']
os.environ['SSH_AGENT_PID'] = agent_data['pid']

process = subprocess.run([SSH_ADD, output_key_path], stderr=subprocess.STDOUT)
if process.returncode != 0:
    raise Exception(f'Failed to add the key: {output_key_path}')
known_hosts = (SSH_DIR / "known_hosts").as_posix()
cmd = "{} -H github.com >> {}".format(SSH_KEYSCAN, known_hosts)

kwargs = {
    'shell':  True,
    'cwd':    REPODIR,
    'stderr': subprocess.STDOUT,
}

p = subprocess.Popen(cmd, **kwargs)
p.wait()

if p.returncode:
    sys.exit(1)

commit_msg = 'Automatic deployment by {}'.format(CI_PRETTY_NAME)
cmds = [
    "{} add .".format(GIT),
    "{} commit -m '{}'".format(GIT, commit_msg),
    "{} ls-files -v".format(GIT),
]

for cmd in cmds:
    logger.info("Running %s", cmd)
    p = subprocess.Popen(cmd, shell=True, cwd=LIEF_PACKAGE_DIR, stderr=subprocess.STDOUT)
    p.wait()

    if p.returncode:
        logger.error("Error while running %s", cmd)
        sys.exit(1)

for i in range(10):
    p = subprocess.Popen("{} push --force {} {}".format(GIT, LIEF_PACKAGE_SSH_REPO, target_branch),
            shell=True, cwd=LIEF_PACKAGE_DIR, stderr=subprocess.STDOUT)
    p.wait()

    if p.returncode == 0:
        break

    cmds = [
        "{} branch -a -v".format(GIT),
        "{} fetch -v origin {}".format(GIT, target_branch),
        "{} branch -a -v".format(GIT),
        "{} rebase -s recursive -X theirs FETCH_HEAD".format(GIT),
        "{} branch -a -v".format(GIT),
    ]
    for c in cmds:
        p = subprocess.Popen(c, shell=True, cwd=LIEF_PACKAGE_DIR, stderr=subprocess.STDOUT)
        p.wait()
else:
    logger.critical("Can't push file on %s -> %s", LIEF_PACKAGE_SSH_REPO, target_branch)
    sys.exit(1)


output_key_path.unlink()
logger.info("Done!")

