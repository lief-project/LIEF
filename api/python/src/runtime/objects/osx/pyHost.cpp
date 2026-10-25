#include "LIEF/runtime/osx/Host.hpp"
#include "runtime/pyRuntime.hpp"

#include "nanobind/stl/string.h"

namespace LIEF::runtime::osx::py {

template<>
void create<Host>(nb::module_& m) {
  nb::class_<Host> obj(m, "Host",
                       "This class exposes OSX-specific host information."_doc);

  using version_t = Host::version_t;
  nb::class_<version_t>(
      obj, "version_t",
      "This class represents a macOS version number (major.minor.patch)."_doc
  )
      .def(nb::init<uint32_t, uint32_t, uint32_t>(), "major"_a, "minor"_a,
           "patch"_a)
      .def_rw("major", &version_t::major, "Major version number"_doc)
      .def_rw("minor", &version_t::minor, "Minor version number"_doc)
      .def_rw("patch", &version_t::patch, "Patch version number"_doc)

      .def("__eq__", &version_t::operator==)
      .def("__ne__", &version_t::operator!=)
      .def("__le__", &version_t::operator<=)
      .def("__gt__", &version_t::operator>)
      .def("__ge__", &version_t::operator>=)
      .def("__lt__",
           [](version_t& self, const version_t& rhs) { return self < rhs; })

      .def_static("big_sur", &version_t::BigSur, nb::rv_policy::reference,
                  "macOS Big Sur (11.0)"_doc)
      .def_static("monterey", &version_t::Monterey, nb::rv_policy::reference,
                  "macOS Monterey (12.0)"_doc)
      .def_static("ventura", &version_t::Ventura, nb::rv_policy::reference,
                  "macOS Ventura (13.0)"_doc)
      .def_static("sonoma", &version_t::Sonoma, nb::rv_policy::reference,
                  "macOS Sonoma (14.0)"_doc)
      .def_static("sequoia", &version_t::Sequoia, nb::rv_policy::reference,
                  "macOS Sequoia (15.0)"_doc)
      .def_static("tahoe", &version_t::Tahoe, nb::rv_policy::reference,
                  "macOS Tahoe (26.0)"_doc)

      .LIEF_DEFAULT_STR(version_t);

  obj.def_prop_ro_static(
         "os_version_name", [](nb::handle) { return Host::os_version_name(); },
         "The operating system version string"_doc
  )

      .def_prop_ro_static(
          "os_version", [](nb::handle) { return Host::os_version(); },
          "The operating system version as a :class:`~.version_t`"_doc
      )

      .def_prop_ro_static(
          "is_sip_enabled", [](nb::handle) { return Host::is_sip_enabled(); },
          R"doc(
          Whether System Integrity Protection (SIP) is enabled on this host.

          This conservatively returns ``True`` when the status can't be determined.
          )doc"_doc
      );
}

}
