#include "pyLIEF.hpp"
#include "LIEF/Object.hpp"

void init_LIEF_Object_class(py::module& m) {
  py::class_<LIEF::Object>(m, "Object");
}
