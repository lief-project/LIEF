#include "LIEF/DWARF/editor/PointerType.hpp"

#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::editor::PointerType>(nb::module_& m) {
  nb::class_<dw::editor::PointerType, dw::editor::Type>(m, "PointerType",
    R"doc(
    This class represents a pointer to another type.
    )doc"_doc
  );
}

}
