#include "LIEF/DWARF/types/Array.hpp"
#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Array>(nb::module_& m) {
  nb::class_<dw::types::Array, dw::Type> type(m, "Array",
    R"doc(
    This class represents a ``DW_TAG_array_type``
    )doc"_doc
  );

  type
    .def_prop_ro("underlying_type", &dw::types::Array::underlying_type,
      R"doc(
      The underlying type of this array.
      )doc"_doc
    )
  ;
}

}
