#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/StringTy.hpp"
#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::StringTy>(nb::module_& m) {
  nb::class_<dw::types::StringTy, dw::Type> type(m, "StringTy",
    R"doc(
    This class represents the ``DW_TAG_string_type`` type
    )doc"_doc
  );
}

}
