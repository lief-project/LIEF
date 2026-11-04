#include "LIEF/runtime/linux/Process.hpp"
#include "runtime/pyRuntime.hpp"

#include "nanobind/stl/string.h"

namespace LIEF::runtime::Linux::py {

template<>
void create<Process>(nb::module_& m) {
  nb::class_<Process, runtime::Process> obj(
      m, "Process",
      "This class exposes Linux-specific API for the current process."_doc
  );

  obj.def_prop_ro_static(
         "cmdline", [](nb::handle) { return Process::cmdline(); },
         "Return the content of ``/proc/cmdline``"_doc
  )

      .def_prop_ro_static(
          "glibc_version", [](nb::handle) { return Process::glibc_version(); },
          R"doc(
          Return the version of the GNU C Library (glibc) loaded in the current
          process (e.g. ``2.39``).

          Return an empty string if the version cannot be determined.
          )doc"_doc
      );
}

}
