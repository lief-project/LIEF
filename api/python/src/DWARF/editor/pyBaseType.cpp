#include "LIEF/DWARF/editor/BaseType.hpp"

#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::editor::BaseType>(nb::module_& m) {
  nb::class_<dw::editor::BaseType, dw::editor::Type> BT(m, "BaseType",
    R"doc(
    This class represents a primitive type like ``int, char``.
    )doc"_doc
  );

  using ENCODING = dw::editor::BaseType::ENCODING;
  nb::enum_<ENCODING>(BT, "ENCODING")
    .value("NONE", ENCODING::NONE)
    .value("ADDRESS", ENCODING::ADDRESS)
    .value("SIGNED", ENCODING::SIGNED)
    .value("SIGNED_CHAR", ENCODING::SIGNED_CHAR)
    .value("UNSIGNED", ENCODING::UNSIGNED)
    .value("UNSIGNED_CHAR", ENCODING::UNSIGNED_CHAR)
    .value("BOOLEAN", ENCODING::BOOLEAN)
    .value("FLOAT", ENCODING::FLOAT)
  ;
}

}
