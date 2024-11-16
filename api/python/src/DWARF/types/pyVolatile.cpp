#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Volatile.hpp"
#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Volatile>(nb::module_& m) {
  nb::class_<dw::types::Volatile, dw::Type> type(m, "Volatile",
    R"doc(
    This class represents a ``DW_TAG_volatile_type``
    )doc"_doc
  );

  type
    .def_prop_ro("underlying_type", &dw::types::Volatile::underlying_type,
      R"doc(
      The underlying type.
      )doc"_doc
    )
  ;
}

}
