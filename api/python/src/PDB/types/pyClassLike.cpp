#include "LIEF/PDB/types/Attribute.hpp"
#include "LIEF/PDB/types/ClassLike.hpp"
#include "LIEF/PDB/types/Method.hpp"
#include "PDB/pyPDB.hpp"

#include <nanobind/make_iterator.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/string_view.h>
#include <nanobind/stl/unique_ptr.h>

#include "pyOwningIterator.hpp"

namespace LIEF::pdb::py {
template<>
void create<pdb::types::ClassLike>(nb::module_& m) {
  nb::class_<pdb::types::ClassLike, pdb::Type> type(m, "ClassLike",
                                                    R"doc(
                                                    This class abstracts the following PDB types: ``LF_STRUCTURE``, ``LF_INTERFACE``,
                                                    ``LF_CLASS`` or ``LF_UNION``.
                                                    )doc"_doc);

  type.def_prop_ro(
          "attributes",
          [](pdb::types::ClassLike& self) {
            auto attrs = LIEF::py::owning_range(self.attributes());
            return nb::make_iterator<nb::rv_policy::reference_internal>(
                nb::type<pdb::types::ClassLike>(), "attributes_it", attrs.begin(),
                attrs.end(), nb::keep_alive<0, 1>()
            );
          },
          R"doc(
          Return an iterator over the different attributes defined in this class-like type
          )doc"_doc,
          nb::keep_alive<0, 1>()
  )

      .def_prop_ro(
          "methods",
          [](pdb::types::ClassLike& self) {
            auto methods = LIEF::py::owning_range(self.methods());
            return nb::make_iterator<nb::rv_policy::reference_internal>(
                nb::type<pdb::types::ClassLike>(), "methods_it", methods.begin(),
                methods.end(), nb::keep_alive<0, 1>()
            );
          },
          R"doc(
          Return an iterator over the different methods implemented in this class-like type
          )doc"_doc,
          nb::keep_alive<0, 1>()
      )

      .def_prop_ro("unique_name", &pdb::types::ClassLike::unique_name,
                   "Mangled type name."_doc);

  nb::class_<pdb::types::Class, pdb::types::ClassLike> clazz(
      m, "Class", "Interface for the ``LF_CLASS`` PDB type"_doc
  );

  nb::class_<pdb::types::Structure, pdb::types::ClassLike> structure(
      m, "Structure", "Interface for the ``LF_STRUCTURE`` PDB type"_doc
  );
  nb::class_<pdb::types::Interface, pdb::types::ClassLike> Interface(
      m, "Interface", "Interface for the ``LF_INTERFACE`` PDB type"_doc
  );

  create<pdb::types::Attribute>(m);
  create<pdb::types::Method>(m);
}

}
