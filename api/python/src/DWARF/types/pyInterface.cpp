#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Interface.hpp"
#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Interface>(nb::module_& m) {
  nb::class_<dw::types::Interface, dw::Type> type(m, "Interface",
    R"doc(
    This class represents the ``DW_TAG_interface_type`` type
    )doc"_doc
  );
}

}
