#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Subroutine.hpp"
#include "LIEF/DWARF/Parameter.hpp"
#include "DWARF/pyDwarf.hpp"

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
    .def_prop_ro("parameters", &dw::types::Subroutine::parameters,
      R"doc(
      Parameters of this subroutine
      )doc"_doc
    )
  ;
}

}
