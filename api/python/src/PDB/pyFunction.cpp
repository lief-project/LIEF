#include "LIEF/PDB/Function.hpp"
#include "PDB/pyPDB.hpp"

#include <nanobind/make_iterator.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

namespace LIEF::pdb::py {
template<>
void create<pdb::Function>(nb::module_& m) {
  nb::class_<pdb::Function> clazz(m, "Function",
    R"doc(
    )doc"_doc
  );
  clazz
    .def_prop_ro("name", &pdb::Function::name,
                 "Name of the function"_doc)

    .def_prop_ro("RVA", &pdb::Function::RVA,
                 "The **Relative** Virtual Address of the function"_doc)

    .def_prop_ro("code_size", &pdb::Function::code_size,
                 "The size of the function"_doc)

    .def_prop_ro("section_name", &pdb::Function::section_name,
                 "The name of the section in which this function is defined"_doc)

    .def_prop_ro("debug_location", &pdb::Function::debug_location,
                 "Original source code location."_doc)
  ;

}

}
