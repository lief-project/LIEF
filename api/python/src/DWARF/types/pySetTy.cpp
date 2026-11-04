#include "DWARF/pyDwarf.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/SetTy.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::SetTy>(nb::module_& m) {
  nb::class_<dw::types::SetTy, dw::Type> type(
      m, "SetTy", "This class represents the ``DW_TAG_set_type`` type"_doc
  );

  type.def_prop_ro("underlying_type", &dw::types::SetTy::underlying_type,
                   "The underlying type referenced by this set-type."_doc,
                   nb::keep_alive<0, 1>());
}

}
