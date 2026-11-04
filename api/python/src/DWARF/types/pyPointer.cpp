#include "DWARF/pyDwarf.hpp"
#include "DWARF/pyTypes.hpp"
#include "LIEF/DWARF/types/Pointer.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Pointer>(nb::module_& m) {
  nb::class_<dw::types::Pointer, dw::Type> type(
      m, "Pointer",
      "This class represents a ``DW_TAG_pointer_type`` DWARF type."_doc
  );

  type.def_prop_ro("underlying_type", &dw::types::Pointer::underlying_type,
                   "The type pointed by this pointer"_doc,
                   nb::rv_policy::reference_internal, nb::keep_alive<0, 1>());
}

}
