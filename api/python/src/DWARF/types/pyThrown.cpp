#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Thrown.hpp"
#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Thrown>(nb::module_& m) {
  nb::class_<dw::types::Thrown, dw::Type> type(m, "Thrown",
    R"doc(
    This class represents a ``DW_TAG_thrown_type``
    )doc"_doc
  );

  type
    .def_prop_ro("underlying_type", &dw::types::Thrown::underlying_type,
      R"doc(
      The underlying type being thrown
      )doc"_doc
    )
  ;
}

}
