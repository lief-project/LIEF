#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/SetTy.hpp"
#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::SetTy>(nb::module_& m) {
  nb::class_<dw::types::SetTy, dw::Type> type(m, "SetTy",
    R"doc(
    This class represents the ``DW_TAG_set_type`` type
    )doc"_doc
  );

  type
    .def_prop_ro("underlying_type", &dw::types::SetTy::underlying_type,
      R"doc(
      The underlying type referenced by this set-type.
      )doc"_doc
    )
  ;
}

}
