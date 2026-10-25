#include "DWARF/pyDwarf.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Const.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Const>(nb::module_& m) {
  nb::class_<dw::types::Const, dw::Type> type(
      m, "Const", "This class represents a ``DW_TAG_const_type`` modifier"_doc
  );

  type.def_prop_ro("underlying_type", &dw::types::Const::underlying_type,
                   "The underlying type being const-ed by this type."_doc,
                   nb::keep_alive<0, 1>());
}

}
