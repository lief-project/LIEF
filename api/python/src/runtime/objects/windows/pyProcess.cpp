#include "LIEF/runtime/windows/PEB.hpp"
#include "LIEF/runtime/windows/Process.hpp"
#include "runtime/pyRuntime.hpp"

#include <nanobind/stl/unique_ptr.h>

namespace LIEF::runtime::windows::py {

template<>
void create<Process>(nb::module_& m) {
  nb::class_<Process, runtime::Process> obj(
      m, "Process",
      "This class exposes Windows-specific API for the current process."_doc
  );

  obj.def_prop_ro_static(
      "peb", [](nb::handle) { return Process::peb(); },
      R"doc(
      Return an interface over the internal Process Environment Block (PEB) of
      the current process.

      Return ``None`` if the PEB cannot be located.
      )doc"_doc
  );
}

}
