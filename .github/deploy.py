#!/usr/bin/env python3
import sys
import os
import re
import logging
import pathlib
import subprocess
import shutil
import json
import itertools
from collections import defaultdict
from datetime import datetime
from mako.template import Template
from enum import Enum, auto
import tempfile
import boto3
from botocore.exceptions import ClientError

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

LOG_LEVEL = logging.INFO

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

ALLOWED_BRANCHES = {"master", "deploy", "devel"}
BRANCH_NAME = get_branch(CURRENT_CI)
TAG_NAME    = get_tag(CURRENT_CI)
IS_TAGGED   = TAG_NAME is not None and len(TAG_NAME) > 0

logger.info("Branch: %s", BRANCH_NAME)
logger.info("Tag:    %s", TAG_NAME)

if BRANCH_NAME.startswith("release-"):
    logger.info("Branch release")
elif BRANCH_NAME not in ALLOWED_BRANCHES and not IS_TAGGED:
    logger.info("Skip deployment for branch '%s'", BRANCH_NAME)
    sys.exit(0)

if is_pr(CURRENT_CI):
    logger.info("Skip pull request")
    sys.exit(0)

CURRENTDIR = pathlib.Path(__file__).resolve().parent
REPODIR    = CURRENTDIR.parent

# According to Scaleway S3 documentation, the endpoint
# should starts with '<bucket>'.s3.<region>.scw.cloud
# Nevertheless boto3 uses /{Bucket} endpoints suffix
# which create issues (see: https://stackoverflow.com/a/70383653)
LIEF_S3_REGION   = "fr-par"
LIEF_S3_ENDPOINT = "https://s3.{region}.scw.cloud".format(region=LIEF_S3_REGION)
LIEF_S3_BUCKET   = "lief"
LIEF_S3_KEY      = os.getenv("LIEF_S3_KEY", None)
LIEF_S3_SECRET   = os.getenv("LIEF_S3_SECRET", None)

if LIEF_S3_KEY is None or len(LIEF_S3_KEY) == 0:
    logger.error("LIEF_S3_KEY is not set!")
    sys.exit(1)

if LIEF_S3_SECRET is None or len(LIEF_S3_SECRET) == 0:
    logger.error("LIEF_S3_SECRET is not set!")
    sys.exit(1)

CI_CWD = pathlib.Path(get_ci_workdir(CURRENT_CI))

if CI_CWD is None:
    logger.error("Can't resolve CI working dir")
    sys.exit(1)

DIST_DIR  = REPODIR / "dist"
BUILD_DIR = REPODIR / "build"

logger.info("Working directory: %s", CI_CWD)

INDEX_TEMPLATE = r"""
<!DOCTYPE html>
<html>
<title>Links for lief</title>
<body>
<h1>Links for lief</h1>
% for path, filename in files:
    <a href="/${path}">${filename}</a><br />
% endfor
</body>
</html>
"""

SKIP_LIST = ["index.html"]

s3 = boto3.resource(
    's3',
    region_name=LIEF_S3_REGION,
    use_ssl=True,
    endpoint_url=LIEF_S3_ENDPOINT,
    aws_access_key_id=LIEF_S3_KEY,
    aws_secret_access_key=LIEF_S3_SECRET
)


def push_wheel(file: str, dir_name: str):
    wheel_file = pathlib.Path(file)
    dst = f"{dir_name}/lief/{wheel_file.name}"
    logger.info("Uploading %s to %s", file, dst)
    try:
        obj = s3.Object(LIEF_S3_BUCKET, dst)
        obj.put(Body=wheel_file.read_bytes())
        return 0
    except ClientError as e:
        logger.error("S3 push failed: %s", e)
        return 1


def push_sdk(file: str, dir_name: str):
    sdk_file = pathlib.Path(file)
    dst = f"{dir_name}/sdk/{sdk_file.name}"
    logger.info("Uploading %s to %s", file, dst)
    try:
        obj = s3.Object(LIEF_S3_BUCKET, dst)
        obj.put(Body=sdk_file.read_bytes())
        return 0
    except ClientError as e:
        logger.error("S3 push failed: %s", e)
        return 1

def filename(object):
    return pathlib.Path(object.key).name

def generate_sdk_index(dir_name: str):
    files = s3.Bucket(LIEF_S3_BUCKET).objects.filter(Prefix=f'{dir_name}/sdk')
    tmpl_info = [(object.key, filename(object)) for object in files if filename(object) not in SKIP_LIST]
    html = Template(INDEX_TEMPLATE).render(files=tmpl_info)
    return html

def generate_pypi_index(dir_name: str):
    files = s3.Bucket(LIEF_S3_BUCKET).objects.filter(Prefix=f'{dir_name}/lief')
    tmpl_info = [(object.key, filename(object)) for object in files if filename(object) not in SKIP_LIST]
    html = Template(INDEX_TEMPLATE).render(files=tmpl_info)
    return html

dir_name = "latest"

if BRANCH_NAME != "master":
    dir_name = "{}".format(BRANCH_NAME.replace("/", "-").replace("_", "-"))

if BRANCH_NAME.startswith("release-"):
    _, dir_name = BRANCH_NAME.split("release-")

if IS_TAGGED:
    dir_name = str(TAG_NAME)

logger.info("Destination directory: %s", dir_name)

for file in DIST_DIR.glob("*.whl"):
    logger.info("[WHEEL] Uploading '%s'", file.as_posix())
    push_wheel(file.as_posix(), dir_name)

for file in itertools.chain(BUILD_DIR.glob("*.zip"), BUILD_DIR.glob("*.tar.gz")):
    logger.info("[SDK  ] Uploading '%s'", file.as_posix())
    push_sdk(file.as_posix(), dir_name)

sdk_index = generate_sdk_index(dir_name)
with tempfile.TemporaryDirectory() as tmp:
    tmp = pathlib.Path(tmp)
    index = (tmp / "index.html")
    index.write_text(sdk_index)
    push_sdk(index.as_posix(), dir_name)

pypi_index = generate_pypi_index(dir_name)
with tempfile.TemporaryDirectory() as tmp:
    tmp = pathlib.Path(tmp)
    index = (tmp / "index.html")
    index.write_text(pypi_index)
    push_wheel(index.as_posix(), dir_name)

logger.info("Done!")

