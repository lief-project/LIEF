#include "DWARF/pyDwarf.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Reference.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Reference>(nb::module_& m) {
  nb::class_<dw::types::Reference, dw::Type> type(
      m, "Reference",
      "This class represents the ``DW_TAG_reference_type`` type"_doc
  );

  type.def_prop_ro("underlying_type", &dw::types::Reference::underlying_type,
                   "The underlying type referenced by this ref-type."_doc,
                   nb::keep_alive<0, 1>());
}

}
