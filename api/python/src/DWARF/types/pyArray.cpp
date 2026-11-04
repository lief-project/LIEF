#include "DWARF/pyDwarf.hpp"
#include "LIEF/DWARF/types/Array.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Array>(nb::module_& m) {
  nb::class_<dw::types::Array, dw::Type> type(
      m, "Array", "This class represents a ``DW_TAG_array_type``"_doc
  );

  nb::class_<dw::types::Array::size_info_t>(
      type, "size_info_t",
      "Class that wraps information about the dimension of this array"_doc
  )
      .def_prop_ro(
          "type",
          [](dw::types::Array::size_info_t& self) { return self.type.get(); },
          R"doc(
          Type of the **index** for this array.

          For instance in ``uint8_t[3]`` the index type could be set to a ``size_t``.
          )doc"_doc,
          nb::keep_alive<0, 1>()
      )
      .def_ro("name", &dw::types::Array::size_info_t::name,
              R"doc(
              Name of the index (usually not relevant like ``__ARRAY_SIZE_TYPE__``)
              )doc"_doc)
      .def_ro(
          "size", &dw::types::Array::size_info_t::size,
          "Size of the array. For instance in ``uint8_t[3]``, it returns 3."_doc
      );

  type.def_prop_ro("underlying_type", &dw::types::Array::underlying_type,
                   "The underlying type of this array."_doc,
                   nb::keep_alive<0, 1>())

      .def_prop_ro("size_info", &dw::types::Array::size_info,
                   R"doc(
                   Return information about the size of this array.

                   This size info is usually embedded in a ``DW_TAG_subrange_type`` DIE which
                   is represented by the :class:`.Array.size_info_t` class.
                   )doc"_doc,
                   nb::keep_alive<0, 1>());
}

}
