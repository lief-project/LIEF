#include "DWARF/pyDwarf.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/StringTy.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::StringTy>(nb::module_& m) {
  nb::class_<dw::types::StringTy, dw::Type> type(
      m, "StringTy", "This class represents the ``DW_TAG_string_type`` type"_doc
  );
}

}
