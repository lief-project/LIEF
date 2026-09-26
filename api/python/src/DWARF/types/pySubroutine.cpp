#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Subroutine.hpp"
#include "LIEF/DWARF/Parameter.hpp"
#include "DWARF/pyDwarf.hpp"
#include "pyutils.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/vector.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Subroutine>(nb::module_& m) {
  nb::class_<dw::types::Subroutine, dw::Type> type(m, "Subroutine",
    R"doc(
    This class represents the ``DW_TAG_subroutine_type`` type
    )doc"_doc
  );

  type
    .def_prop_ro("return_type", &dw::types::Subroutine::return_type,
      R"doc(
      Return the :class:`~.dwarf.Type` associated with the **return type** of this
      function
      )doc"_doc, nb::keep_alive<0, 1>()
    )
    .def_prop_ro("parameters", &dw::types::Subroutine::parameters,
      R"doc(
      Parameters of this subroutine
      )doc"_doc, nb::call_policy<LIEF::py::returns_references_to<1>>()
    )
  ;
}

}
