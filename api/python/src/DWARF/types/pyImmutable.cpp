#include "DWARF/pyDwarf.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Immutable.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Immutable>(nb::module_& m) {
  nb::class_<dw::types::Immutable, dw::Type> type(
      m, "Immutable",
      "This class represents the ``DW_TAG_immutable_type`` type"_doc
  );


  type.def_prop_ro("underlying_type", &dw::types::Immutable::underlying_type,
                   "The underlying type."_doc, nb::keep_alive<0, 1>());
}

}
