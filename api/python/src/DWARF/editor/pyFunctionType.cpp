#include "LIEF/DWARF/editor/FunctionType.hpp"

#include "DWARF/pyDwarf.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::editor::FunctionType>(nb::module_& m) {
  nb::class_<dw::editor::FunctionType, dw::editor::Type> F(m, "FunctionType",
    R"doc(
    This class represents a function type (``DW_TAG_subroutine_type``)
    )doc"_doc
  );

  nb::class_<dw::editor::FunctionType::Parameter> FP(F, "Parameter",
    "This class represents a function's parameter"_doc
  );
  F
    .def("set_return_type", &dw::editor::FunctionType::set_return_type,
         "Set the return type of this function"_doc,
         "type"_a, nb::rv_policy::reference_internal)

    .def("add_parameter", &dw::editor::FunctionType::add_parameter,
         "Add a parameter"_doc, "type"_a)
  ;
}

}
