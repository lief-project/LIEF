#include "DWARF/pyDwarf.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/RValueRef.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::RValueReference>(nb::module_& m) {
  nb::class_<dw::types::RValueReference, dw::Type> type(
      m, "RValueReference",
      "This class represents the ``DW_TAG_rvalue_reference_type`` type"_doc
  );

  type.def_prop_ro("underlying_type", &dw::types::RValueReference::underlying_type,
                   "The underlying type referenced by this rvalue-type."_doc,
                   nb::keep_alive<0, 1>());
}

}
