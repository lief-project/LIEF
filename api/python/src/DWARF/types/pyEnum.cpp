#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Enum.hpp"
#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Enum>(nb::module_& m) {
  nb::class_<dw::types::Enum, dw::Type> type(m, "Enum",
    R"doc(
    This class represents the ``DW_TAG_enumeration_type`` type
    )doc"_doc
  );
}

}
