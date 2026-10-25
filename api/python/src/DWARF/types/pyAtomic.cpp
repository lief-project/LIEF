#include "DWARF/pyDwarf.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Atomic.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Atomic>(nb::module_& m) {
  nb::class_<dw::types::Atomic, dw::Type> type(
      m, "Atomic", "This class represents the ``DW_TAG_atomic_type`` type"_doc
  );

  type.def_prop_ro("underlying_type", &dw::types::Atomic::underlying_type,
                   "The underlying type being atomized by this type."_doc,
                   nb::keep_alive<0, 1>());
}

}
