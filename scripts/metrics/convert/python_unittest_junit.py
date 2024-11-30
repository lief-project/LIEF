#!python
import sys
import argparse
from pathlib import Path
sys.path.insert(0, (Path(__file__).parent / "..").as_posix())
from models import Metrics
from models.python import Metrics as PythonMetrics
from models.python.unittest import Metrics as PythonUnittestMetrics
from lxml import etree

def convert(tree) -> str:
    if tree.tag != 'testsuites' or len(tree) == 0:
        raise RuntimeError(f"Expecting a <testsuite> tag at the beginning ({tree.tag})")

    testsuite = tree[0]
    nb_errors = testsuite.get("errors", 0)
    nb_failures = testsuite.get("failures", 0)
    nb_skipped = testsuite.get("skipped", 0)
    nb_tests = testsuite.get("tests", 0)
    time = float(testsuite.get("time"))
    timestamp = testsuite.get("timestamp")

    metrics = Metrics(
        python=PythonMetrics(
            unittest=PythonUnittestMetrics(
                duration=time,
                nb_tests=nb_tests,
                nb_errors=nb_errors,
                nb_failures=nb_failures,
                nb_skipped=nb_skipped,
            )
        )
    )
    return metrics.model_dump_json()

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        metavar="FILE",
        type=Path,
        dest='junit_xml_report',
        required=True
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        type=Path,
        dest='json_output',
        required=True
    )

    args = parser.parse_args()

    input_file: Path = args.junit_xml_report
    output_file: Path = args.json_output
    if not input_file.is_file():
        print(f"{input_file} does not exist")
        return 1

    content = input_file.read_bytes()
    if len(content) == 0:
        print(f"{input_file} is empty")
        return 0

    root = etree.fromstring(input_file.read_bytes())
    output_file.write_text(convert(root))
    return 0

if __name__ == "__main__":
    sys.exit(main())
