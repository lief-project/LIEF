import lief
from pathlib import Path

def _remove_eol(string: str):
    return string.replace("\n", "").replace("\r", "")

def test_filesink(tmp_path: Path):
    lief.logging.log(lief.logging.LEVEL.ERROR, "hello from default sink")
    out_log = tmp_path / "lief.log"
    lief.logging.set_path(out_log)
    lief.logging.log(lief.logging.LEVEL.ERROR, "hello")
    assert out_log.read_text() == "hello\n"
    lief.logging.reset()

def test_stderr(capsys):
    lief.logging.log(lief.logging.LEVEL.ERROR, "This is an error")
    lief.logging.log(lief.logging.LEVEL.ERROR, "This is another error")

    captured = capsys.readouterr()
    assert _remove_eol(captured.err) == "This is an errorThis is another error"

def test_context_manager(capsys):
    lief.logging.reset()
    lief.logging.set_level(lief.logging.LEVEL.ERROR)
    assert lief.logging.get_level() == lief.logging.LEVEL.ERROR
    with lief.logging.level_scope(lief.logging.LEVEL.INFO):
        assert lief.logging.get_level() == lief.logging.LEVEL.INFO
        lief.logging.log(lief.logging.LEVEL.INFO, "This is an info message")
    captured = capsys.readouterr()
    assert _remove_eol(captured.err) == "This is an info message"
    assert lief.logging.get_level() == lief.logging.LEVEL.ERROR
