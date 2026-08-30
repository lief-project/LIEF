#include <sstream>
#include "LIEF/runtime/MemoryLayout.hpp"
#include "runtime/pyRuntime.hpp"

#include <nanobind/make_iterator.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/string_view.h>
#include <nanobind/stl/unique_ptr.h>

#include "pyOwningIterator.hpp"

namespace LIEF::runtime::py {

template<>
void create<MemoryLayout>(nb::module_& m) {
  nb::class_<MemoryLayout> obj(m, "MemoryLayout",
    R"doc(
    This class exposes the memory layout of the current process.
    )doc"_doc
  );

  using Region = MemoryLayout::Region;
  nb::class_<Region>(obj, "Region",
    R"doc(
    A contiguous range of memory mapped in the current process.
    )doc"_doc
  )
    .def_prop_ro("name", &Region::name,
      R"doc(
      Name associated with the region: the name or the path of the module
      mapped at this address (e.g. ``libc.so.6``) or the identifier of a
      region that is not backed by a file (e.g. ``[stack]``, ``[heap]``).

      It can be empty for anonymous regions.
      )doc"_doc
    )
    .def_prop_ro("addr", &Region::addr,
      "Address at which the region starts"_doc
    )
    .def_prop_ro("size", &Region::size,
      "Size of the region"_doc
    )
    .def_prop_ro("end_addr", &Region::end_addr,
      "Address at which the region ends"_doc
    )
    .def("contains", &Region::contains, "addr"_a,
      "Whether the given address is within this region"_doc
    )
    LIEF_DEFAULT_STR(Region)
  ;

  m.def("memory_layout", [] () {
    auto layout = LIEF::py::owning_range(runtime::memory_layout());
    return nb::make_iterator<nb::rv_policy::take_ownership>(
      nb::type<Region>(), "memory_layout_iterator", layout);
  }, R"doc(
  Return an iterator over the memory layout of the current process
  )doc"_doc);
}

}
