#include "LIEF/PDB/CompilationUnit.hpp"
#include "PDB/pyPDB.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/make_iterator.h>

namespace LIEF::pdb::py {
template<>
void create<pdb::CompilationUnit>(nb::module_& m) {
  nb::class_<pdb::CompilationUnit>(m, "CompilationUnit",
    R"doc(
    This class represents a Compilation Unit (or Module) in a PDB file
    )doc"_doc
  )
    .def_prop_ro("module_name", &pdb::CompilationUnit::module_name,
      R"doc(
      Name (or path) to the COFF object (``.obj``) associated with this
      compilation unit (e.g. ``e:\obj.amd64fre\minkernel\ntos\hvl\mp\objfre\amd64\hvlp.obj``)
      )doc"_doc
    )

    .def_prop_ro("object_filename", &pdb::CompilationUnit::object_filename,
      R"doc(
      Name of path to the original binary object (COFF, Archive) in which
      the compilation unit was located before being linked.
      e.g. ``e:\obj.amd64fre\minkernel\ntos\hvl\mp\objfre\amd64\hvl.lib``
      )doc"_doc
    )

    .def_prop_ro("sources",
        [] (const pdb::CompilationUnit& self) {
          auto sources = self.sources();
          return nb::make_iterator(
              nb::type<pdb::CompilationUnit>(), "sources_it", sources);
        },
      R"doc(
      Iterator over the sources files that compose this compilation unit.
      These files include **headers** (``.h, .hpp``, ...).
      )doc"_doc, nb::keep_alive<0, 1>()
    )
    .def_prop_ro("functions",
        [] (const pdb::CompilationUnit& self) {
          auto functions = self.functions();
          return nb::make_iterator(
              nb::type<pdb::CompilationUnit>(), "functions_it", functions);
        },
      R"doc(
      Return an iterator over the function defined in this compilation unit.
      If the PDB does not contain or has an empty DBI stream, it returns
      an empty iterator.
      )doc"_doc, nb::keep_alive<0, 1>()
    )
  ;
}

}
