#!python
import sys
import os
import argparse
sys.path.insert(0, os.path.dirname(__file__))

from models import Metrics
from models.python.unittest import Metrics as PythonUnittestMetrics
from models.cpp.unittest import Metrics as CppUnittestMetrics
from typing import Optional, Dict, Any, Tuple
from functools import lru_cache
from pathlib import Path
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

from influxdb_client.client.write_api import SYNCHRONOUS
from influxdb_client import InfluxDBClient, Point

class InfluxSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix='influx_')
    url: str
    token: str
    bucket: str = "LIEF"
    org: str = "server"

class Config(BaseSettings):
    influx: InfluxSettings = InfluxSettings()

class Serialize:
    def __init__(self, metrics: Metrics,
                 platform: str, arch: str,
                 commit: Optional[str] = None,
                 machine: Optional[str] = None,
                 tags: list[Tuple[str, str]] = []):
        self.metrics = metrics
        self.platform = platform
        self.arch = arch
        self.commit = commit
        self.machine = machine
        self.tags = tags

    def _attach_tags(self, record: Point) -> 'Serialize':
        record.tag("arch", self.arch)
        record.tag("platform", self.platform)
        if self.machine is not None:
            record.tag("machine", self.machine)

        for k, v in self.tags:
            record.tag(k, v)
        return self

    def _attach_generic_fields(self, record: Point) -> 'Serialize':
        if self.commit is not None:
            record.field("commit", self.commit)
        return self

    def _serialize_metrics(self, name: str, metrics: BaseModel) -> Optional[Point]:
        fields: Dict[str, Any] = metrics.model_dump(
            exclude_none=True, exclude_unset=True
        )

        if len(fields) == 0:
            return None

        record = Point.measurement(name)
        self._attach_tags(record) \
            ._attach_generic_fields(record)

        for k, v in fields.items():
            record.field(k, v)
        return record

    def serialize(self) -> list[Point]:
        points: list[Point] = []
        if python := self.metrics.python:
            if unittest := python.unittest:
                if rec := self._serialize_metrics("python_unittest", unittest):
                    points.append(rec)
            if native_library_info := python.native_library:
                if rec := self._serialize_metrics("python_native_library", native_library_info):
                    points.append(rec)

        if cpp := self.metrics.cpp:
            if unittest := cpp.unittest:
                if rec := self._serialize_metrics("cpp_unittest", unittest):
                    points.append(rec)

            if memory := cpp.memory:
                if rec := self._serialize_metrics("memory_consumption", memory):
                    points.append(rec)
        return points

@lru_cache(maxsize=1)
def config() -> Config:
    return Config()

@lru_cache()
def client() -> InfluxDBClient:
    conf = config()
    return InfluxDBClient(url=conf.influx.url, token=conf.influx.token, org=conf.influx.org)

def push_metrics(metrics: Metrics, platform: str, arch: str,
                 commit: Optional[str] = None, machine: Optional[str] = None,
                 tags: list[Tuple[str, str]] = [],
                 ) -> int:
    conf = config()
    api = client().write_api(write_options=SYNCHRONOUS)
    serializer = Serialize(metrics, platform, arch, commit, machine, tags)
    count = 0
    for record in serializer.serialize():
        count += 1
        api.write(bucket=conf.influx.bucket, record=record)
    return count

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--file",
        metavar="FILE",
        type=Path,
        dest='metrics_file',
        required=True,
        nargs='+'
    )

    parser.add_argument(
        "--platform",
        metavar="PLATFORM",
        type=str,
        dest='metrics_platform',
        required=True
    )

    parser.add_argument(
        "--architecture",
        metavar="ARCHITECTURE",
        type=str,
        dest='metrics_architecture',
        required=True
    )

    parser.add_argument(
        "--commit",
        metavar="COMMIT",
        type=str,
        dest='metrics_commit',
        default=None
    )

    parser.add_argument(
        "--machine",
        metavar="MACHINE",
        type=str,
        dest='metrics_machine',
        default=None
    )

    parser.add_argument(
        "--tags",
        metavar="TAGS",
        type=str,
        dest='metrics_tags',
        required=False,
        nargs='*',
        default=[]
    )

    args = parser.parse_args()

    files: list[Path] = args.metrics_file
    platform: str = args.metrics_platform
    arch: str = args.metrics_architecture
    commit: Optional[str] = args.metrics_commit
    machine: Optional[str] = args.metrics_machine
    arg_tags: list[str] = args.metrics_tags

    tags: list[Tuple[str, str]] = []
    for tag in arg_tags:
        k, v = tag.split('=')
        tags.append((k, v))

    count = 0
    for file in files:
        metrics = Metrics.model_validate_json(file.read_bytes())
        count += push_metrics(metrics, platform, arch, commit, machine, tags)

    files_str = ", ".join([f.as_posix() for f in files])
    print(f"#{count} metrics pushed for {platform}-{arch} from {files_str} ({commit})")
    return 0

if __name__ == "__main__":
    sys.exit(main())
