#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Dynamic.hpp"
#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Dynamic>(nb::module_& m) {
  nb::class_<dw::types::Dynamic, dw::Type> type(m, "Dynamic",
    R"doc(
    This class represents the ``DW_TAG_dynamic_type`` type
    )doc"_doc
  );
}

}
