#include "LIEF/PDB/types/Attribute.hpp"
#include "PDB/pyPDB.hpp"
#include "PDB/pyType.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/string_view.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::pdb::py {
template<>
void create<pdb::types::Attribute>(nb::module_& m) {
  nb::class_<pdb::types::Attribute> type(
      m, "Attribute",
      R"doc(
      This class represents an attribute (``LF_MEMBER``) in an aggregate (class,
      struct, union, ...)
      )doc"_doc
  );

  type.def_prop_ro("name", &pdb::types::Attribute::name,
                   "Name of this attribute."_doc)

      .def_prop_ro("type", &pdb::types::Attribute::type,
                   "Type of this attribute"_doc, nb::keep_alive<0, 1>())
      .def_prop_ro("field_offset", &pdb::types::Attribute::field_offset,
                   "Offset of this attribute in the aggregate"_doc);
}

}
