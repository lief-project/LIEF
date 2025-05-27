#include "LIEF/DWARF/editor/TypeDef.hpp"

#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::editor::TypeDef>(nb::module_& m) {
  nb::class_<dw::editor::TypeDef, dw::editor::Type>(m, "TypeDef",
    "This class represents a typedef (``DW_TAG_typedef``)."_doc
  );
}

}
