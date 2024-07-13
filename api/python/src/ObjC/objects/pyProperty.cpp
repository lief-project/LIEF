#include "ObjC/pyObjC.hpp"
#include "LIEF/ObjC/Property.hpp"

#include <nanobind/stl/string.h>

namespace LIEF::objc::py {
template<>
void create<objc::Property>(nb::module_& m) {
  nb::class_<objc::Property> prop(m, "Property",
    R"doc(
    This class represents a ``@property`` in Objective-C
    )doc"_doc
  );

  prop
    .def_prop_ro("name", &objc::Property::name,
      R"doc(
      Name of the property
      )doc"_doc
    )
    .def_prop_ro("attribute", &objc::Property::attribute,
      R"doc(
      (raw) property's attributes (e.g. ``T@"NSString",C,D,N``)
      )doc"_doc
    )
  ;
}

}
