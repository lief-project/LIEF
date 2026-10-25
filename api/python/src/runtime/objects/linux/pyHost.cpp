#include "LIEF/runtime/linux/Host.hpp"
#include "runtime/pyRuntime.hpp"

#include "nanobind/stl/string.h"

namespace LIEF::runtime::Linux::py {

template<>
void create<Host>(nb::module_& m) {
  nb::class_<Host>(m, "Host",
                   "This class exposes Linux-specific host information."_doc)
      .def_prop_ro_static(
          "sys_name", [](nb::handle) { return Host::sys_name(); },
          "Operating system name (e.g. ``Linux``)"_doc
      )

      .def_prop_ro_static(
          "sys_release", [](nb::handle) { return Host::sys_release(); },
          "Operating system release (e.g. ``2.6.28``)"_doc
      )

      .def_prop_ro_static(
          "sys_version", [](nb::handle) { return Host::sys_version(); },
          "Operating system version"_doc
      )

      .def_prop_ro_static(
          "hardware", [](nb::handle) { return Host::hardware(); },
          "Hardware type identifier (e.g. ``x86_64``)"_doc
      );
}

}
