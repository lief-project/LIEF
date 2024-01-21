#!/usr/bin/env python3
from botocore.exceptions import ClientError
from mako.template import Template
from pathlib import Path
from typing import Any, Optional

import argparse
import boto3
import functools
import logging
import os
import sys
import tempfile
import tomli
import re

LOG_LEVEL = logging.INFO

CURRENTDIR      = Path(__file__).resolve().parent
REPODIR         = CURRENTDIR.parent
ASSET_DIR       = CURRENTDIR / "assets"
CONFIG_DIR      = CURRENTDIR / "config"
LIEF_S3_KEY     = os.getenv("LIEF_S3_KEY", None)
LIEF_S3_SECRET  = os.getenv("LIEF_S3_SECRET", None)
OWNED_ORGS      = ["lief-project/", "romainthomas/"]
RELEASE_KEYWORD = ["release-", "release/"]

DEFAULT_CONFIG   = CONFIG_DIR / "gh-ci.toml"
DEFAULT_TEMPLATE = (ASSET_DIR / "index.j2").read_text()

logging.getLogger().addHandler(logging.StreamHandler(stream=sys.stdout))
logging.getLogger().setLevel(LOG_LEVEL)
logger = logging.getLogger(__name__)

if LIEF_S3_KEY is None or len(LIEF_S3_KEY) == 0:
    logger.error("LIEF_S3_KEY is not set!")

if LIEF_S3_SECRET is None or len(LIEF_S3_SECRET) == 0:
    logger.error("LIEF_S3_SECRET is not set!")

class S3Manager:
    def __init__(self, dirname: str, bucket: str,
                       region: str, endpoint: str,
                       dry_run: bool = False):
        self._s3_dirname: str = dirname
        self._s3_bucket: str = bucket
        self._s3_region: str = region
        self._s3_endpoint: str = endpoint
        self._dry_run: bool = dry_run

        logger.info("[S3] Bucket  : %s", self._s3_bucket)
        logger.info("[S3] Region  : %s", self._s3_region)
        logger.info("[S3] Endpoint: %s", self._s3_endpoint)
        logger.info("[S3] Dir     : %s", self._s3_dirname)

    def change_dir(self, dirname: str):
        self._s3_dirname = dirname

    @property
    def s3_lief_sdk(self) -> str:
        return f"{self._s3_dirname}/sdk"

    @property
    def s3_lief_wheel(self) -> str:
        return f"{self._s3_dirname}/lief"

    @property
    def url(self):
        return f"https://{self._s3_bucket}.s3-website.{self._s3_region}.scw.cloud/{self._s3_dirname}"

    @functools.lru_cache(maxsize=1)
    def s3(self) -> boto3.Session:
        s3_res = boto3.resource(
            's3',
            region_name=self._s3_region,
            use_ssl=True,
            endpoint_url=self._s3_endpoint,
            aws_access_key_id=LIEF_S3_KEY,
            aws_secret_access_key=LIEF_S3_SECRET
        )
        return s3_res

    @classmethod
    def from_config(cls, config):
        pass

    def _s3_push(self, file: Path, dst: str):
        logger.info("Uploading %s to %s", file, dst)
        try:
            obj = self.s3().Object(self._s3_bucket, dst)
            if not self._dry_run:
                obj.put(Body=file.read_bytes())
            else:
                logger.info("[--] put: %s/%s - %s", self._s3_bucket, dst, file.as_posix())
            return 0
        except ClientError as e:
            logger.error("S3 push failed: %s", e)
            return 1

    def push_wheel(self, file: str):
        wheel_file = Path(file)
        if not wheel_file.is_file():
            logger.error("'%s' is not a valid file!", wheel_file)
            return

        dst = f"{self.s3_lief_wheel}/{wheel_file.name}"
        self._s3_push(wheel_file, dst)

    def push_sdk(self, file: str):
        sdk_path = Path(file)
        if not sdk_path.is_file():
            logger.error("'%s' is not a valid file!", sdk_path)
            return

        dst = f"{self.s3_lief_sdk}/{sdk_path.name}"
        self._s3_push(sdk_path, dst)

    def push_content(self, content: str, dst: str):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            index = tmp_path / "index.html"
            index.write_text(content)
            self._s3_push(index, dst)

    def process_sdk_wheels(self, directory: Path, maxdepth: int = 0,
                           depth: int = 0, recurse: bool = True):
        logger.info("Processing directory: %s", directory)
        for item in directory.iterdir():
            if item.is_dir() and recurse:
                if 0 < maxdepth < depth:
                    logger.debug("Maximum iteration depth reached")
                else:
                    self.process_sdk_wheels(item, maxdepth, depth + 1, recurse)
            elif item.is_file():
                extension = item.suffix
                if extension in (".zip", ".gz"):
                    logger.info("[SDK  ] Uploading '%s'", item.as_posix())
                    self.push_sdk(item.as_posix())
                elif extension in (".whl", ):
                    logger.info("[WHEEL] Uploading '%s'", item.as_posix())
                    self.push_wheel(item.as_posix())


    def upload_wheels_sdk(self, src_dir: Path, maxdepth: int):
        logger.info("Looking for wheels and sdk from: %s", src_dir)
        self.process_sdk_wheels(src_dir, maxdepth=maxdepth, recurse=True)

        wheels_index = self.generate_index(self.s3_lief_wheel,
                                           DEFAULT_TEMPLATE,
                                           skiplist=("index.html", ))

        sdk_index = self.generate_index(self.s3_lief_sdk, DEFAULT_TEMPLATE,
                                        skiplist=("index.html", ))

        self.push_content(wheels_index, f"{self.s3_lief_wheel}/index.html")
        self.push_content(sdk_index, f"{self.s3_lief_sdk}/index.html")

        logger.info("Done!")
        logger.info("URL: %s/%s", self.url, "sdk")
        logger.info("URL: %s/%s", self.url, "lief")

    def s3_list(self, dirname: str) -> list[Any]:
        if self._dry_run:
            return []
        return self.s3().Bucket(self._s3_bucket).objects.filter(Prefix=dirname)

    def generate_index(self, dirname: str, template: str, skiplist=None):
        files = self.s3_list(dirname)
        selected_files = []
        for s3_object in files:
            filename = Path(s3_object.key).name
            if skiplist is not None and filename in skiplist:
                continue
            selected_files.append((s3_object.key, filename))
        return Template(template).render(files=selected_files)

class GithubDeploy:
    def __init__(self, branches: list[str],
                       main_branches: list[str],
                       default_dir: str,
                       s3_manager: S3Manager):
        self.s3_manager: S3Manager = s3_manager

        self._branches: list[str] = branches
        self._main_branches: list[str] = main_branches
        self._default_dir: str = default_dir


    @classmethod
    def from_config(cls, config_file: Path):
        with open(config_file, "rb") as f:
            toml_config = tomli.load(f)

        if "lief" not in toml_config:
            logger.warning("Missing lief entries in '%s'", config_file)
            return None
        lief_conf = toml_config["lief"]

        if "s3" not in lief_conf:
            logger.warning("Missing lief.s3 entries in '%s'", config_file)
            return None

        if "deploy" not in lief_conf:
            logger.warning("Missing lief.deploy entries in '%s'", config_file)
            return None

        branches = lief_conf["deploy"]["branches"]
        main_branches = lief_conf["deploy"]["main-branches"]
        default_dir = lief_conf["deploy"]["default-dir"]
        s3_config = lief_conf["s3"]
        s3_region = s3_config["region"]
        s3_bucket = s3_config["bucket"]
        s3_endpoint = s3_config["endpoint"]

        s3_manager = S3Manager(default_dir, s3_bucket, s3_region, s3_endpoint)
        return cls(branches, main_branches, default_dir, s3_manager)

    @staticmethod
    def branch() -> Optional[str]:
        ref = os.getenv("GITHUB_REF")
        if ref is None:
            return None
        return ref.replace("refs/heads/", "")

    @staticmethod
    def is_pr() -> bool:
        head_ref = os.getenv("GITHUB_HEAD_REF", "")
        repo_path = os.getenv("GITHUB_REPOSITORY", "")
        is_owned_repo = any(repo_path.startswith(org) for org in OWNED_ORGS)
        return head_ref != "" or not is_owned_repo

    @staticmethod
    def is_tagged() -> bool:
        tag = GithubDeploy.tag_name()
        return tag is not None and len(tag) > 0

    @staticmethod
    def tag_name() -> Optional[str]:
        ref = os.getenv("GITHUB_REF", "")
        logger.info("Github Action tag: %s", ref)
        if ref.startswith("refs/tags/"):
            return ref.replace("refs/tags/", "")
        return ""

    @staticmethod
    def workspace() -> str:
        return os.getenv("GITHUB_WORKSPACE", "")

    def is_main_branch(self, name: str) -> bool:
        return name in self._main_branches

    def should_be_deployed(self, branch: str) -> bool:
        if GithubDeploy.is_tagged():
            return True

        if any(re.match(s, branch) for s in self._branches):
            return True

        if any(branch.startswith(e) for e in RELEASE_KEYWORD):
            return True

        return False

    def deploy(self, directories: list[str]):
        s3dir = None
        tag = None
        if GithubDeploy.is_tagged():
            s3dir = GithubDeploy.tag_name()
            tag = s3dir if len(s3dir) > 0 else None
            logger.info("Deployment for tag: %s", tag)
        else:
            branch = GithubDeploy.branch()
            if branch is None:
                logger.warning("Can't resolve the branch name")
                sys.exit(1)

            for rel_kwrd in RELEASE_KEYWORD:
                if branch.startswith(rel_kwrd):
                    _, s3dir = branch.split(rel_kwrd)
            if s3dir is None:

                if self.is_main_branch(branch):
                    s3dir = self._default_dir
                else:
                    s3dir = branch.replace("/", "-").replace("_", "-")

            if not self.should_be_deployed(branch):
                logger.info("Skipping deployment for branch: %s", branch)
                return

        if s3dir is None:
            logger.error("Target directory is not set")
            sys.exit(1)

        logger.info("s3dir: %s", s3dir)
        self.s3_manager.change_dir(s3dir)
        for dirname in directories:
            dirpath = Path(dirname).resolve().absolute().expanduser()
            self.s3_manager.upload_wheels_sdk(dirpath, maxdepth=1)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c")
    parser.add_argument("--dry-run", "-n", action="store_true", default=False)
    parser.add_argument("directories", nargs="+")

    args = parser.parse_args()
    config_path = None
    if args.config is not None:
        config_path = Path(args.config)
    else:
        config_path = DEFAULT_CONFIG

    if not config_path.is_file():
        logger.error("'%s' is not a valid config path")
        sys.exit(1)

    gh_deploy = GithubDeploy.from_config(config_path)
    gh_deploy.deploy(args.directories)

if __name__ == "__main__":
    main()
    sys.exit(0)
