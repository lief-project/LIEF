#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/TemplateAlias.hpp"
#include "LIEF/DWARF/Parameter.hpp"
#include "DWARF/pyDwarf.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/vector.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::types::TemplateAlias>(nb::module_& m) {
  nb::class_<dw::types::TemplateAlias, dw::Type> type(m, "TemplateAlias",
    R"doc(
    This class represents the ``DW_TAG_template_alias`` type
    )doc"_doc
  );

  type
    .def_prop_ro("parameters", &dw::types::TemplateAlias::parameters,
      R"doc(
      Parameters associated with the underlying template
      )doc"_doc
    )

    .def_prop_ro("underlying_type", &dw::types::TemplateAlias::underlying_type,
      R"doc(
      The underlying type aliased by this type.
      )doc"_doc
    )
  ;
}

}
