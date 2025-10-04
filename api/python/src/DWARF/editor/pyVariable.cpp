#include "LIEF/DWARF/editor/Variable.hpp"
#include "LIEF/DWARF/editor/Type.hpp"

#include "DWARF/pyDwarf.hpp"

#include <nanobind/stl/string.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::editor::Variable>(nb::module_& m) {
  nb::class_<dw::editor::Variable> V(m, "Variable",
    R"doc(
    This class represents an **editable** DWARF variable which can be
    scoped by a function or a compilation unit (``DW_TAG_variable``)
    )doc"_doc
  );

  V
    .def("set_addr", &dw::editor::Variable::set_addr,
      R"doc(
      Set the global address of this variable. Setting this address is only
      revelant in the case of a static global variable. For stack variable, you
      should use :meth:`~.Variable.set_stack_offset`.

      This function set the ``DW_AT_location`` attribute
      )doc"_doc, "addr"_a, nb::rv_policy::reference_internal)

    .def("set_stack_offset", &dw::editor::Variable::set_stack_offset,
      R"doc(
      Set the stack offset of this variable.

      This function set the ``DW_AT_location`` attribute
      )doc"_doc, "offset"_a, nb::rv_policy::reference_internal)

    .def("set_external", &dw::editor::Variable::set_external,
      R"doc(
      Mark this variable as **imported**
      )doc"_doc, nb::rv_policy::reference_internal)

    .def("set_type", &dw::editor::Variable::set_type,
      R"doc(
      Set the type of the current variable
      )doc"_doc, "type"_a, nb::rv_policy::reference_internal)

    .def("add_description", &dw::editor::Variable::add_description,
      R"doc(
      Create a ``DW_AT_description`` entry with the description
      provided in parameter.
      )doc"_doc, "description"_a, nb::rv_policy::reference_internal)
  ;
}

}
