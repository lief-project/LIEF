#include "DWARF/pyDwarf.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Shared.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Shared>(nb::module_& m) {
  nb::class_<dw::types::Shared, dw::Type> type(
      m, "Shared", "This class represents the ``DW_TAG_shared_type`` type"_doc
  );

  type.def_prop_ro("underlying_type", &dw::types::Shared::underlying_type,
                   "The underlying type referenced by this shared-type."_doc,
                   nb::keep_alive<0, 1>());
}

}
