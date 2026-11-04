#include "LIEF/runtime/Host.hpp"
#include "runtime/pyRuntime.hpp"

#include "nanobind/stl/string.h"

namespace LIEF::runtime::py {
template<>
void create<Host>(nb::module_& m) {
  nb::class_<Host> obj(m, "Host", "This class represents the current host."_doc);

  obj.def_prop_ro_static(
         "name", [](nb::handle) { return Host::name(); },
         "The machine hostname"_doc
  )

      .def_prop_ro_static(
          "home_dir", [](nb::handle) { return Host::home_dir(); }, R"doc(
          The user home dir (e.g. ``/home/romain`` or ``C:\Users\romain``)
          )doc"_doc
      )

      .def_prop_ro_static(
          "tmp_dir", [](nb::handle) { return Host::tmp_dir(); }, R"doc(
          Temporary directory.

          This function looks at the environment variables to determine the suitable
          temp directory (e.g. ``TEMP``, ``TMPDIR``)
          )doc"_doc
      )

      .def_prop_ro_static(
          "config_dir", [](nb::handle) { return Host::config_dir(); },
          "The directory to store user-specific configuration"_doc
      )

      .def_prop_ro_static(
          "cache_dir", [](nb::handle) { return Host::cache_dir(); }, R"doc(
          The directory where software should store their cache files
          (e.g. ``$HOME/.cache``)
          )doc"_doc
      );
}

}
