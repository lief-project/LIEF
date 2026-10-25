#include "DWARF/pyDwarf.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Restrict.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Restrict>(nb::module_& m) {
  nb::class_<dw::types::Restrict, dw::Type> type(
      m, "Restrict", "This class represents the ``DW_TAG_restrict_type`` type"_doc
  );

  type.def_prop_ro("underlying_type", &dw::types::Restrict::underlying_type,
                   "The underlying type referenced by this restrict-type."_doc,
                   nb::keep_alive<0, 1>());
}

}
