#include "LIEF/runtime/android/Host.hpp"
#include "runtime/pyRuntime.hpp"

#include <nanobind/stl/optional.h>

namespace LIEF::runtime::android::py {

template<>
void create<Host>(nb::module_& m) {
  nb::class_<Host>(m, "Host",
    R"doc(
    This class exposes Android-specific host information.
    )doc"_doc
  )
    .def_prop_ro_static("sdk_version", [] (nb::handle) {
      return Host::sdk_version();
    },
    R"doc(
    Return the Android SDK/API level of the device (e.g. ``34`` for Android 14).
    )doc"_doc)
  ;
}

}
