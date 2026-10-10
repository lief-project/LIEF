import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import pytest
from utils import address_space_limiter, get_sample


@pytest.mark.parametrize("test_name", ["pr_1371_0.exe", "pr_1371_1.exe"])
def test_aarch64_epilog_scopes_dos(test_name: str):
    sample = Path(get_sample(f"PE/{test_name}")).absolute()

    code = dedent("""\
    import lief
    import sys
    lief.logging.disable()
    config = lief.PE.ParserConfig()
    config.parse_exceptions = True
    pe = lief.PE.parse(sys.argv[1], config)
    assert pe is not None
    scopes = sum(len(e.epilog_scopes) for e in pe.exceptions
                 if isinstance(e, lief.PE.unwind_aarch64.UnpackedFunction))
    assert scopes < 1_000_000, scopes
    print("OK")""")

    stdout = subprocess.check_output(
        [sys.executable, "-c", code, str(sample)],
        timeout=60.0,
        preexec_fn=address_space_limiter(),
    )

    assert b"OK" in stdout


@pytest.mark.private
def test_patch_address_out_of_segment():
    GAP = 0x20_000_000
    sample = Path(get_sample("private/PE/bss_issue.exe")).absolute()

    code = dedent(f"""\
    import lief
    import sys
    lief.logging.disable()
    pe = lief.PE.parse(sys.argv[1])
    sec = next(s for s in pe.sections if s.virtual_size > len(s.content) > 0)
    rva = sec.virtual_address + len(sec.content) + {GAP // 2}
    pe.patch_address(rva, 0x4141414141414141, 8, lief.Binary.VA_TYPES.RVA)
    print("OK")""")

    stdout = subprocess.check_output(
        [sys.executable, "-c", code, str(sample)],
        timeout=60.0,
        preexec_fn=address_space_limiter(),
    )

    assert b"OK" in stdout
