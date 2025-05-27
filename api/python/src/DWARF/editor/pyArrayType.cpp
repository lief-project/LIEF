#include "LIEF/DWARF/editor/ArrayType.hpp"

#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::editor::ArrayType>(nb::module_& m) {
  nb::class_<dw::editor::ArrayType, dw::editor::Type>(m, "ArrayType",
    R"doc(
    This class represents an array type.
    )doc"_doc
  );
}

}
