#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Shared.hpp"
#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Shared>(nb::module_& m) {
  nb::class_<dw::types::Shared, dw::Type> type(m, "Shared",
    R"doc(
    This class represents the ``DW_TAG_shared_type`` type
    )doc"_doc
  );

  type
    .def_prop_ro("underlying_type", &dw::types::Shared::underlying_type,
      R"doc(
      The underlying type referenced by this shared-type.
      )doc"_doc
    )
  ;
}

}
