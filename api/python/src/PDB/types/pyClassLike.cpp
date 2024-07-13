#include "LIEF/PDB/types/ClassLike.hpp"
#include "LIEF/PDB/types/Attribute.hpp"
#include "LIEF/PDB/types/Method.hpp"
#include "PDB/pyPDB.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/make_iterator.h>

namespace LIEF::pdb::py {
template<>
void create<pdb::types::ClassLike>(nb::module_& m) {
  nb::class_<pdb::types::ClassLike, pdb::Type> type(m, "ClassLike",
    R"doc(
    This class abstracts the following PDB types: ``LF_STRUCTURE``, ``LF_INTERFACE``,
    ``LF_CLASS`` or ``LF_UNION``.
    )doc"_doc
  );

  type
    .def_prop_ro("attributes",
      [] (pdb::types::ClassLike& self) {
        auto attrs = self.attributes();
        return nb::make_iterator(
            nb::type<pdb::types::ClassLike>(), "attributes_it", attrs);
      },
      R"doc(
      Return an iterator over the different attributes defined in this class-like type
      )doc"_doc, nb::keep_alive<0, 1>())

    .def_prop_ro("methods",
      [] (pdb::types::ClassLike& self) {
        auto methods = self.methods();
        return nb::make_iterator(
            nb::type<pdb::types::ClassLike>(), "methods_it", methods);
      },
      R"doc(
      Return an iterator over the different methods implemented in this class-like type
      )doc"_doc, nb::keep_alive<0, 1>())

    .def_prop_ro("unique_name", &pdb::types::ClassLike::unique_name,
      R"doc(
      Mangled type name.
      )doc"_doc
    )

    .def_prop_ro("name", &pdb::types::ClassLike::name,
      R"doc(
      Demangled type name
      )doc"_doc
    )

    .def_prop_ro("size", &pdb::types::ClassLike::size,
      R"doc(
      Size of the the type including all its attributes. This size should match
      the ``sizeof(...)`` this type.
      )doc"_doc
    )
  ;

  nb::class_<pdb::types::Class, pdb::types::ClassLike> clazz(m, "Class",
    R"doc(
    Interface for the ``LF_CLASS`` PDB type
    )doc"_doc
  );

  nb::class_<pdb::types::Structure, pdb::types::ClassLike> structure(m, "Structure",
    R"doc(
    Interface for the ``LF_STRUCTURE`` PDB type
    )doc"_doc
  );
  nb::class_<pdb::types::Interface, pdb::types::ClassLike> Interface(m, "Interface",
    R"doc(
    Interface for the ``LF_INTERFACE`` PDB type
    )doc"_doc
  );

  create<pdb::types::Attribute>(m);
  create<pdb::types::Method>(m);
}

}
