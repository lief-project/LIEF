#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Typedef.hpp"
#include "DWARF/pyDwarf.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Typedef>(nb::module_& m) {
  nb::class_<dw::types::Typedef, dw::Type> type(m, "Typedef",
    R"doc(
    This class represents a ``DW_TAG_typedef`` type
    )doc"_doc
  );

  type
    .def_prop_ro("underlying_type", &dw::types::Typedef::underlying_type,
      R"doc(
      The type aliased by this typedef
      )doc"_doc
    )
  ;
}

}
