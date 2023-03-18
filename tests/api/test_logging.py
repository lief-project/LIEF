import lief
from pathlib import Path

def test_filesink(tmp_path: Path):
    lief.logging.log(lief.logging.LOGGING_LEVEL.ERROR, "hello from default sink")
    out_log = tmp_path / "lief.log"
    lief.logging.set_path(out_log.as_posix())
    lief.logging.log(lief.logging.LOGGING_LEVEL.ERROR, "hello")
    assert out_log.read_text() == "hello\n"

