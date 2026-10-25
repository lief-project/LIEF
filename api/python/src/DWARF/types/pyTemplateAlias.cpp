#include "DWARF/pyDwarf.hpp"
#include "LIEF/DWARF/Parameter.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/TemplateAlias.hpp"
#include "pyutils.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/vector.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::types::TemplateAlias>(nb::module_& m) {
  nb::class_<dw::types::TemplateAlias, dw::Type> type(
      m, "TemplateAlias",
      "This class represents the ``DW_TAG_template_alias`` type"_doc
  );

  type.def_prop_ro("parameters", &dw::types::TemplateAlias::parameters,
                   "Parameters associated with the underlying template"_doc,
                   nb::call_policy<LIEF::py::returns_references_to<1>>())

      .def_prop_ro("underlying_type", &dw::types::TemplateAlias::underlying_type,
                   "The underlying type aliased by this type."_doc,
                   nb::keep_alive<0, 1>());
}

}
