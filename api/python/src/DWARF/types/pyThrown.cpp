#include "DWARF/pyDwarf.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Thrown.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Thrown>(nb::module_& m) {
  nb::class_<dw::types::Thrown, dw::Type> type(
      m, "Thrown", "This class represents a ``DW_TAG_thrown_type``"_doc
  );

  type.def_prop_ro("underlying_type", &dw::types::Thrown::underlying_type,
                   "The underlying type being thrown"_doc, nb::keep_alive<0, 1>());
}

}
