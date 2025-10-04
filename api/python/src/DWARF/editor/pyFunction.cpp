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

  using range_t = dw::editor::Function::range_t;
  nb::class_<range_t>(F, "range_t")
    .def(nb::init<>())
    .def(nb::init<uint64_t, uint64_t>(), "start"_a, "end"_a)
    .def_rw("start", &range_t::start)
    .def_rw("end", &range_t::end);

  using Parameter = dw::editor::Function::Parameter;
  nb::class_<Parameter> FP(F, "Parameter",
    R"doc(
    This class represents a parameter of the current function (``DW_TAG_formal_parameter``)
    )doc"_doc
  );

  FP
    .def("assign_register", nb::overload_cast<const std::string&>(&Parameter::assign_register),
      "Assign this parameter to a specific named register."_doc,
      nb::rv_policy::reference_internal
    )
    .def("assign_register", nb::overload_cast<uint64_t>(&Parameter::assign_register),
      R"doc(Assign this parameter to the given DWARF register id (e.g. ``DW_OP_reg0``))doc"_doc,
      nb::rv_policy::reference_internal
    );

  using LexicalBlock = dw::editor::Function::LexicalBlock;
  nb::class_<LexicalBlock> FLB(F, "LexicalBlock",
    "This class mirrors the ``DW_TAG_lexical_block`` DWARF tag"_doc
  );

  FLB
    .def("add_block", nb::overload_cast<uint64_t, uint64_t>(&LexicalBlock::add_block),
      R"doc(
      Create a sub-block with the given low/high addresses.

      If the function managed to create the new block, it returns
      the newly created block, otherwise it returns the current block
      )doc"_doc, "start"_a, "end"_a, nb::rv_policy::reference_internal
    )

    .def("add_block", nb::overload_cast<const std::vector<range_t>&>(&LexicalBlock::add_block),
      R"doc(
      Create a sub-block with the given range of addresses.

      If the function managed to create the new block, it returns
      the newly created block, otherwise it returns the current block
      )doc"_doc, "range"_a, nb::rv_policy::reference_internal
    )

    .def("add_description", &LexicalBlock::add_description,
      R"doc(
      Create a ``DW_AT_description`` entry with the description
      provided in parameter.
      )doc"_doc, "description"_a, nb::rv_policy::reference_internal
    )

    .def("add_name", &LexicalBlock::add_name,
      R"doc(
      Create a ``DW_AT_name`` entry to associate a name to this entry
      )doc"_doc, "name"_a, nb::rv_policy::reference_internal
    )
  ;

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

    .def("add_description", &dw::editor::Function::add_description,
      R"doc(
      Create a `DW_AT_description` entry with the description
      provided in parameter.
      )doc"_doc, "description"_a, nb::rv_policy::reference_internal)
  ;
}

}
