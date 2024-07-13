#include "LIEF/DWARF/types/Pointer.hpp"
#include "DWARF/pyDwarf.hpp"
#include "DWARF/pyTypes.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Pointer>(nb::module_& m) {
  nb::class_<dw::types::Pointer, dw::Type> type(m, "Pointer",
    R"doc(
    This class represents a ``DW_TAG_pointer_type`` DWARF type.
    )doc"_doc
  );

  type
    .def_prop_ro("underlying_type", &dw::types::Pointer::underlying_type,
      R"doc(
      The type pointed by this pointer
      )doc"_doc, nb::rv_policy::reference_internal
    )
  ;
}

}
