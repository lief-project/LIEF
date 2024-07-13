#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Const.hpp"
#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Const>(nb::module_& m) {
  nb::class_<dw::types::Const, dw::Type> type(m, "Const",
    R"doc(
    This class represents a ``DW_TAG_const_type`` modifier
    )doc"_doc
  );

  type
    .def_prop_ro("underlying_type", &dw::types::Const::underlying_type,
      R"doc(
      The underlying type being const-ed by this type.
      )doc"_doc
    )
  ;
}

}
