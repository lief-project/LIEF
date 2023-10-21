import lief
from pathlib import Path

def test_filesink(tmp_path: Path):
    lief.logging.log(lief.logging.LOGGING_LEVEL.ERROR, "hello from default sink")
    out_log = tmp_path / "lief.log"
    lief.logging.set_path(out_log.as_posix())
    lief.logging.log(lief.logging.LOGGING_LEVEL.ERROR, "hello")
    assert out_log.read_text() == "hello\n"
    lief.logging.reset()

def test_stderr(capsys):
    lief.logging.log(lief.logging.LOGGING_LEVEL.ERROR, "This is an error")
    lief.logging.log(lief.logging.LOGGING_LEVEL.ERROR, "This is another error")

    captured = capsys.readouterr()
    assert captured.err == "This is an error\nThis is another error\n"

def test_stderr(capsys):
    lief.logging.log(lief.logging.LOGGING_LEVEL.ERROR, "This is an error")
    lief.logging.log(lief.logging.LOGGING_LEVEL.ERROR, "This is another error")

    captured = capsys.readouterr()
    assert captured.err == "This is an error\nThis is another error\n"

