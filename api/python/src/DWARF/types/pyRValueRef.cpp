#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/RValueRef.hpp"
#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::RValueReference>(nb::module_& m) {
  nb::class_<dw::types::RValueReference, dw::Type> type(m, "RValueReference",
    R"doc(
    This class represents the ``DW_TAG_rvalue_reference_type`` type
    )doc"_doc
  );

  type
    .def_prop_ro("underlying_type", &dw::types::RValueReference::underlying_type,
      R"doc(
      The underlying type referenced by this rvalue-type.
      )doc"_doc
    )

  ;
}

}
