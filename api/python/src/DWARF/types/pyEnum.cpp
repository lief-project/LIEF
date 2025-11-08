#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/Enum.hpp"
#include "DWARF/pyDwarf.hpp"

#include "nanobind/extra/stl/lief_optional.h"

#include <nanobind/stl/vector.h>
#include <nanobind/stl/string.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Enum>(nb::module_& m) {
  using Enum = dw::types::Enum;
  nb::class_<Enum, dw::Type> type(m, "Enum",
    R"doc(
    This class represents the ``DW_TAG_enumeration_type`` type
    )doc"_doc
  );

  nb::class_<Enum::Entry>(type, "Entry",
    R"doc(
    This class represents an enum entry which is essentially composed of a
    name and its value (integer).
    )doc"_doc
  )
    .def_prop_ro("name", &Enum::Entry::name,
      "Enum entry's name"_doc
    )

    .def_prop_ro("value", &Enum::Entry::value,
      "Enum entry's value"_doc
    )
  ;

  type
    .def_prop_ro("entries", &Enum::entries,
      "Entries associated with this enum"_doc
    )

    .def_prop_ro("underlying_type", &Enum::underlying_type,
      "The underlying type that is used to encode this enum"_doc,
      nb::rv_policy::reference_internal
    )

    .def("find_entry", &Enum::find_entry,
      "Try to find the entry matching the given value"_doc,
      "value"_a
    )
  ;
}

}
