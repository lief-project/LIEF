#include "LIEF/PDB/types/Attribute.hpp"
#include "PDB/pyPDB.hpp"
#include "PDB/pyType.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

namespace LIEF::pdb::py {
template<>
void create<pdb::types::Attribute>(nb::module_& m) {
  nb::class_<pdb::types::Attribute> type(m, "Attribute",
    R"doc(
    This class represents an attribute (``LF_MEMBER``) in an aggregate (class,
    struct, union, ...)
    )doc"_doc
  );

  type
    .def_prop_ro("name", &pdb::types::Attribute::name,
      R"doc(
      Name of this attribute.
      )doc"_doc
    )

    .def_prop_ro("type", &pdb::types::Attribute::type,
      R"doc(
      Type of this attribute
      )doc"_doc
    )
    .def_prop_ro("field_offset", &pdb::types::Attribute::field_offset,
      R"doc(
      Offset of this attribute in the aggregate
      )doc"_doc
    )
  ;
}

}
