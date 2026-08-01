#include "LIEF/runtime/android/Property.hpp"
#include "runtime/pyRuntime.hpp"

#include <sstream>

#include <nanobind/stl/string.h>
#include <nanobind/stl/string_view.h>

namespace LIEF::runtime::android::py {

template<>
void create<Property>(nb::module_& m) {
  nb::class_<Property> obj(m, "Property",
    R"doc(
    This class represents an Android system property such as ``ro.boot.hardware``.
    )doc"_doc
  );

  obj
    .def_prop_ro("name", &Property::name,
      "Name of the property (e.g. ``ro.boot.hardware``)"_doc)

    .def_prop_ro("value", &Property::value,
      "Value associated with the property"_doc)

    .def_prop_ro("serial", &Property::serial,
      R"doc(
      Serial number of the property.
      )doc"_doc)

    LIEF_DEFAULT_STR(Property)
  ;
}

}
