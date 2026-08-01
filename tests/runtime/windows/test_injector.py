import sys

import lief
import pytest
from utils import resolve_runtime_library

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)

if lief.runtime.platform != lief.runtime.PLATFORMS.WINDOWS:
    pytest.skip("skipping: windows only", allow_module_level=True)


@pytest.mark.runtime
def test_simple():
    lief.logging.enable_debug()

    library = resolve_runtime_library("runtime-simple-lib")
    library = library.resolve().absolute()
    assert library.is_file()

    ctx = lief.runtime.windows.injection_context_t()
    ctx.args = f"{sys.executable} --version"
    ctx.library = str(library)

    print(library)
    assert library.is_file()
    lief.runtime.windows.inject_spawn(ctx)
