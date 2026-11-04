#include "LIEF/runtime/windows/Host.hpp"
#include "runtime/pyRuntime.hpp"

#include "nanobind/stl/string.h"

namespace LIEF::runtime::windows::py {

template<>
void create<Host>(nb::module_& m) {
  nb::class_<Host> obj(
      m, "Host", "This class exposes Windows-specific host information."_doc
  );

  using version_t = Host::version_t;
  nb::class_<version_t>(obj, "version_t",
                        "This class represents a Windows version number."_doc)
      .def(nb::init<>())
      .def(nb::init<uint32_t, uint32_t, uint32_t>(), "major"_a, "minor"_a,
           "build_number"_a)
      .def_rw("major", &version_t::major, "Major version number"_doc)
      .def_rw("minor", &version_t::minor, "Minor version number"_doc)
      .def_rw("build_number", &version_t::build_number, "Build number"_doc)

      .def("__eq__", &version_t::operator==)
      .def("__ne__", &version_t::operator!=)
      .def("__le__", &version_t::operator<=)
      .def("__gt__", &version_t::operator>)
      .def("__ge__", &version_t::operator>=)
      .def("__lt__", &version_t::operator<)

      .LIEF_DEFAULT_STR(version_t);

  obj.def_prop_ro_static(
      "version", [](nb::handle) { return Host::version(); },
      "The Windows version (e.g. ``10.0.26200``)"_doc
  );
}

}
