#include "ObjC/pyObjC.hpp"
#include "LIEF/ObjC/Method.hpp"

#include <nanobind/stl/string.h>

namespace LIEF::objc::py {
template<>
void create<objc::Method>(nb::module_& m) {
  nb::class_<objc::Method> meth(m, "Method",
    R"doc(
    This class represents an Objective-C Method.
    )doc"_doc
  );
  meth
    .def_prop_ro("name", &objc::Method::name,
      R"doc(
      Name of the method
      )doc"_doc
    )
    .def_prop_ro("mangled_type", &objc::Method::mangled_type,
      R"doc(
      Prototype of the method in its mangled representation (e.g. ``@16@0:8``)
      )doc"_doc
    )
    .def_prop_ro("address", &objc::Method::address,
      R"doc(
      Virtual address where this method is implemented in the binary
      )doc"_doc
    )
    .def_prop_ro("is_instance", &objc::Method::is_instance,
      R"doc(
      Whether it's an instance method or not.
      )doc"_doc
    )
  ;
}

}
