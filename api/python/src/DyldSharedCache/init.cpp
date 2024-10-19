#include "DyldSharedCache/init.hpp"
#include "DyldSharedCache/pyDyldSharedCache.hpp"
#include "LIEF/DyldSharedCache/caching.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::dsc {
class DyldSharedCache;
class Dylib;
class SubCache;
class MappingInfo;
}

namespace LIEF::dsc::py {
void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("dsc");

  mod.def("enable_cache", nb::overload_cast<>(&enable_cache),
    R"doc(
    Enable globally cache/memoization. One can also leverage this function
    by setting the environment variable ``DYLDSC_ENABLE_CACHE`` to ``1``

    By default, LIEF will use the directory specified by the environment
    variable ``DYLDSC_CACHE_DIR`` as its cache-root directory:

    .. code-block:: console

      DYLDSC_ENABLE_CACHE=1 DYLDSC_CACHE_DIR=/tmp/my_dir python ./my-script.py

    Otherwise, if ``DYLDSC_CACHE_DIR`` is not set, LIEF will use the following
    directory (in this priority):

    1. System or user cache directory

      - macOS: ``DARWIN_USER_TEMP_DIR`` / ``DARWIN_USER_CACHE_DIR`` + ``/dyld_shared_cache``
      - Linux: ``${XDG_CACHE_HOME}/dyld_shared_cache``
      - Windows: ``%LOCALAPPDATA%\dyld_shared_cache``

    2. Home directory

      - macOS/Linux: ``$HOME/.dyld_shared_cache``
      - Windows: ``%USERPROFILE%\.dyld_shared_cache``

    See :meth:`lief.dsc.DyldSharedCache.enable_caching` for a finer granularity
    )doc"_doc
  );

  mod.def("enable_cache", nb::overload_cast<const std::string&>(&enable_cache),
    R"doc(
    Same behavior as the other :meth:`~.enable_cache` function but using a
    user-provided cache directory instead of an inferred one.
    )doc"_doc, "target_cache_dir"_a
  );

  create<LIEF::dsc::DyldSharedCache>(mod);
  create<LIEF::dsc::Dylib>(mod);
  create<LIEF::dsc::SubCache>(mod);
  create<LIEF::dsc::MappingInfo>(mod);
}
}
