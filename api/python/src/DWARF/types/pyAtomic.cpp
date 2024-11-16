#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Atomic.hpp"
#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Atomic>(nb::module_& m) {
  nb::class_<dw::types::Atomic, dw::Type> type(m, "Atomic",
    R"doc(
    This class represents the ``DW_TAG_atomic_type`` type
    )doc"_doc
  );

  type
    .def_prop_ro("underlying_type", &dw::types::Atomic::underlying_type,
      R"doc(
      The underlying type being atomized by this type.
      )doc"_doc
    )
  ;
}

}
