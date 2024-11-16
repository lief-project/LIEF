#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Immutable.hpp"
#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Immutable>(nb::module_& m) {
  nb::class_<dw::types::Immutable, dw::Type> type(m, "Immutable",
    R"doc(
    This class represents the ``DW_TAG_immutable_type`` type
    )doc"_doc
  );


  type
    .def_prop_ro("underlying_type", &dw::types::Immutable::underlying_type,
      R"doc(
      The underlying type.
      )doc"_doc
    )
  ;
}

}
