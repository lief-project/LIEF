#include "LIEF/PDB/types/Enum.hpp"
#include "PDB/pyPDB.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include "nanobind/extra/stl/lief_optional.h"

namespace LIEF::pdb::py {
template<>
void create<pdb::types::Enum>(nb::module_& m) {
  using Enum = pdb::types::Enum;
  nb::class_<Enum, pdb::Type> type(m, "Enum",
    R"doc(
    This class represents a ``LF_ENUM`` PDB type
    )doc"_doc
  );

  nb::class_<Enum::Entry> entry(type, "Entry",
    R"doc(
    This class represents an enum entry which is essentially composed of a name
    and its value (integer).
    )doc"_doc
  );

  entry
    .def_prop_ro("name", &Enum::Entry::name,
      "Enum entry's name"_doc
    )

    .def_prop_ro("value", &Enum::Entry::value,
      "Enum entry's value (if any)"_doc
    )
  ;

  type
    .def_prop_ro("unique_name", &Enum::unique_name,
      "Enum's mangled name"_doc
    )

    .def_prop_ro("entries", &Enum::entries,
      "Return the different entries associated with this enum"_doc
    )

    .def_prop_ro("underlying_type", &Enum::underlying_type,
      "The underlying type that is used to encode this enum"_doc
    )

    .def("find_entry", &Enum::find_entry,
      "Try to find the enum matching the given value"_doc,
      "value"_a
    )
  ;

}

}
