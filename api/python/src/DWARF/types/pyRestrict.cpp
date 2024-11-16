#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Restrict.hpp"
#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Restrict>(nb::module_& m) {
  nb::class_<dw::types::Restrict, dw::Type> type(m, "Restrict",
    R"doc(
    This class represents the ``DW_TAG_restrict_type`` type
    )doc"_doc
  );

  type
    .def_prop_ro("underlying_type", &dw::types::Restrict::underlying_type,
      R"doc(
      The underlying type referenced by this restrict-type.
      )doc"_doc
    )
  ;
}

}
