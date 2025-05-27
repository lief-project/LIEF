#include "LIEF/DWARF/editor/Function.hpp"
#include "LIEF/DWARF/editor/Variable.hpp"
#include "LIEF/DWARF/editor/Type.hpp"

#include "DWARF/pyDwarf.hpp"

#include <nanobind/stl/vector.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::editor::Function>(nb::module_& m) {
  nb::class_<dw::editor::Function> F(m, "Function",
    R"doc(
    This class represents an **editable** DWARF function (``DW_TAG_subprogram``)
    )doc"_doc
  );

  nb::class_<dw::editor::Function::range_t>(F, "range_t")
    .def(nb::init<>())
    .def(nb::init<uint64_t, uint64_t>(), "start"_a, "end"_a)
    .def_rw("start", &dw::editor::Function::range_t::start)
    .def_rw("end", &dw::editor::Function::range_t::end);

  nb::class_<dw::editor::Function::Parameter> FP(F, "Parameter",
    R"doc(
    This class represents a parameter of the current function (``DW_TAG_formal_parameter``)
    )doc"_doc
  );

  nb::class_<dw::editor::Function::LexicalBlock> FLB(F, "LexicalBlock",
    "This class mirrors the `DW_TAG_lexical_block` DWARF tag"_doc
  );

  nb::class_<dw::editor::Function::Label> FL(F, "Label",
    "This class mirrors the ``DW_TAG_label`` DWARF tag"_doc
  );

  F
    .def("set_address", &dw::editor::Function::set_address,
         "Set the address of this function by defining ``DW_AT_entry_pc``"_doc,
         "addr"_a, nb::rv_policy::reference_internal)

    .def("set_low_high", &dw::editor::Function::set_low_high,
         R"doc(
         Set the upper and lower bound addresses for this function. This assumes
         that the function is contiguous between ``low`` and ``high``.

         Underneath, the function defines ``DW_AT_low_pc`` and ``DW_AT_high_pc``
         )doc"_doc, "low"_a, "high"_a, nb::rv_policy::reference_internal)

    .def("set_ranges", &dw::editor::Function::set_ranges,
         R"doc(
         Set the ranges of addresses owned by the implementation of this function
         by setting the ``DW_AT_ranges`` attribute.

         This setter should be used for non-contiguous function.
         )doc"_doc, "ranges"_a, nb::rv_policy::reference_internal)

    .def("set_external", &dw::editor::Function::set_external,
         R"doc(
         Set the function as external by defining ``DW_AT_external`` to true.
         This means that the function is **imported** by the current compilation
         unit.)doc"_doc, nb::rv_policy::reference_internal)

    .def("set_return_type", &dw::editor::Function::set_return_type,
         "Set the return type of this function"_doc,
         "type"_a, nb::rv_policy::reference_internal)

    .def("add_parameter", &dw::editor::Function::add_parameter,
         "Add a parameter to the current function"_doc,
         "name"_a, "type"_a)

    .def("create_stack_variable", &dw::editor::Function::create_stack_variable,
         "Create a stack-based variable owned by the current function"_doc,
         "name"_a)

    .def("add_lexical_block", &dw::editor::Function::add_lexical_block,
         "Add a lexical block with the given range"_doc,
         "start"_a, "end"_a)

    .def("add_label", &dw::editor::Function::add_label,
         "Add a label at the given address"_doc,
         "addr"_a, "label"_a)
  ;
}

}
