#include "LIEF/runtime/osx/Process.hpp"
#include "runtime/pyRuntime.hpp"

#include "nanobind/stl/string.h"

namespace LIEF::runtime::osx::py {

template<>
void create<Process>(nb::module_& m) {
  nb::class_<Process, runtime::Process> obj(
      m, "Process",
      "This class exposes OSX-specific API for the current process."_doc
  );

  obj.def_prop_ro_static(
      "dyld_version", [](nb::handle) { return Process::dyld_version(); },
      "Return the version of dyld for the current process"_doc
  );
}

}
