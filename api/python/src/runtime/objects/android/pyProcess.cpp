#include "LIEF/runtime/android/Process.hpp"
#include "runtime/pyRuntime.hpp"

#include "nanobind/stl/string.h"
#include "nanobind/stl/vector.h"
#include <nanobind/stl/optional.h>

namespace LIEF::runtime::android::py {

template<>
void create<Process>(nb::module_& m) {
  nb::class_<Process, runtime::Process> obj(m, "Process",
    R"doc(
    This class exposes Android-specific API for the current process.
    )doc"_doc
  );

  obj
    .def_prop_ro_static("cmdline", [] (nb::handle) {
      return Process::cmdline();
    },
    R"doc(
    Return the content of ``/proc/cmdline``
    )doc"_doc)

    .def_static("get_system_property", &Process::get_system_property, "name"_a,
    R"doc(
    Return the value of the Android system property with the given ``name``
    (e.g. ``ro.build.version.sdk``).
    )doc"_doc)

    .def_prop_ro_static("properties", [] (nb::handle) {
      return Process::properties();
    },
    R"doc(
    Return all the Android system properties as a list of
    :class:`~lief.runtime.android.Property`.
    )doc"_doc)
  ;
}

}
