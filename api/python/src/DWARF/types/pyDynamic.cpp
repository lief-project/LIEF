#include "DWARF/pyDwarf.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Dynamic.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Dynamic>(nb::module_& m) {
  nb::class_<dw::types::Dynamic, dw::Type> type(
      m, "Dynamic", "This class represents the ``DW_TAG_dynamic_type`` type"_doc
  );
}

}
