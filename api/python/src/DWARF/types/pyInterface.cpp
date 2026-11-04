#include "DWARF/pyDwarf.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Interface.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Interface>(nb::module_& m) {
  nb::class_<dw::types::Interface, dw::Type> type(
      m, "Interface",
      "This class represents the ``DW_TAG_interface_type`` type"_doc
  );
}

}
