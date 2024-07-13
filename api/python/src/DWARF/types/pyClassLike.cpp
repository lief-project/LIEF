#include "LIEF/DWARF/types/ClassLike.hpp"
#include "DWARF/pyDwarf.hpp"

#include <nanobind/stl/vector.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

#include "pyErr.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::ClassLike>(nb::module_& m) {
  nb::class_<dw::types::ClassLike, dw::Type> class_like(m, "ClassLike",
    R"doc(
    This class abstracts a DWARF aggregate (``DW_TAG_structure_type``,
    ``DW_TAG_class_type``, ``DW_TAG_union_type``).
    )doc"_doc
  );

  nb::class_<dw::types::ClassLike::Member>(class_like, "Member",
    R"doc(
    This class represents a class/struct/union attribute.
    )doc"_doc
  )
    .def_prop_ro("name", &dw::types::ClassLike::Member::name,
      R"doc(
      Name of the member
      )doc"_doc
    )

    .def_prop_ro("type", &dw::types::ClassLike::Member::type,
      R"doc(
      Type of the current member
      )doc"_doc
    )

    .def_prop_ro("is_external", &dw::types::ClassLike::Member::is_external,
      R"doc(
      )doc"_doc
    )

    .def_prop_ro("is_declaration", &dw::types::ClassLike::Member::is_declaration,
      R"doc(
      )doc"_doc
    )

    .def_prop_ro("offset",
      [] (const dw::types::ClassLike::Member& self) {
        return LIEF::py::value_or_none(&dw::types::ClassLike::Member::offset, self);
      },
      R"doc(
      Offset of the current member in the struct/union/class

      If the offset can't be resolved it returns None
      )doc"_doc
    )
    .def_prop_ro("bit_offset",
      [] (const dw::types::ClassLike::Member& self) {
        return LIEF::py::value_or_none(&dw::types::ClassLike::Member::bit_offset, self);
      },
      R"doc(
      Offset of the current member in **bits** in the current struct/union/class

      This function differs from :attr:`~.offset` for aggregates using bit-field
      declaration:

      .. code-block:: cpp

          struct S {
            int flag : 4;
            int opt : 1
          };

      Usually, ``offset * 8 == bit_offset``

      If the offset can't be resolved it returns None
      )doc"_doc
    )
  ;

  class_like
    .def_prop_ro("members", &dw::types::ClassLike::members,
      R"doc(
      Return a list of all the members defined in this class-like type.
      )doc"_doc
    )
    .def("find_member", &dw::types::ClassLike::find_member,
      R"doc(
      Try to find the attribute at the given offset
      )doc"_doc, "offset"_a
    )
  ;

  nb::class_<dw::types::Structure, dw::types::ClassLike> Struct(m, "Structure",
    R"doc(
    This class represents a DWARF ``struct`` type (``DW_TAG_structure_type``)
    )doc"_doc
  );

  nb::class_<dw::types::Class, dw::types::ClassLike> Class(m, "Class",
    R"doc(
    This class represents a DWARF ``class`` type (``DW_TAG_class_type``)
    )doc"_doc
  );

  nb::class_<dw::types::Union, dw::types::ClassLike> Union(m, "Union",
    R"doc(
    This class represents a DWARF ``union`` type (``DW_TAG_union_type``)
    )doc"_doc
  );
}

}
