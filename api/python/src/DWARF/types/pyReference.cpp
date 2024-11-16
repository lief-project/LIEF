#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Reference.hpp"
#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Reference>(nb::module_& m) {
  nb::class_<dw::types::Reference, dw::Type> type(m, "Reference",
    R"doc(
    This class represents the ``DW_TAG_reference_type`` type
    )doc"_doc
  );

  type
    .def_prop_ro("underlying_type", &dw::types::Reference::underlying_type,
      R"doc(
      The underlying type referenced by this ref-type.
      )doc"_doc
    )
  ;
}

}
