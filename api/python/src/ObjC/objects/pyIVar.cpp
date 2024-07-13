#include "ObjC/pyObjC.hpp"
#include "LIEF/ObjC/IVar.hpp"

#include <nanobind/stl/string.h>

namespace LIEF::objc::py {
template<>
void create<objc::IVar>(nb::module_& m) {
  nb::class_<objc::IVar> ivar(m, "IVar",
    R"doc(
    This class represents an instance variable (ivar)
    )doc"_doc
  );
  ivar
    .def_prop_ro("name", &objc::IVar::name,
      R"doc(
      Name of the instance variable
      )doc"_doc
    )
    .def_prop_ro("mangled_type", &objc::IVar::mangled_type,
      R"doc(
      Type of the instance var in its mangled representation (e.g. ``[29i]``)
      )doc"_doc
    )
  ;

}

}
