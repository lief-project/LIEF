#include "LIEF/DyldSharedCache/SubCache.hpp"
#include "LIEF/DyldSharedCache/DyldSharedCache.hpp"
#include "DyldSharedCache/pyDyldSharedCache.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/array.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/make_iterator.h>

namespace LIEF::dsc::py {
template<>
void create<dsc::SubCache>(nb::module_& m) {
  nb::class_<dsc::SubCache> obj(m, "SubCache",
    R"doc(
    This class represents a subcache in the case of large/split dyld shared
    cache.

    It mirror (and abstracts) the original ``dyld_subcache_entry`` / ``dyld_subcache_entry_v1``
    )doc"_doc
  );

  obj
    .def_prop_ro("uuid", &SubCache::uuid,
      R"doc(The uuid of the subcache file)doc"_doc
    )
    .def_prop_ro("vm_offset", &SubCache::vm_offset,
      R"doc(The offset of this subcache from the main cache base address)doc"_doc
    )
    .def_prop_ro("suffix", &SubCache::suffix,
      R"doc(
      The file name suffix of the subCache file
      (e.g. ``.25.data``, ``.03.development``)
      )doc"_doc
    )
    .def_prop_ro("cache", [] (const SubCache& self) {
        return std::unique_ptr<DyldSharedCache>(const_cast<DyldSharedCache*>(self.cache().release()));
      },
      R"doc(
      The associated :class:`~.DyldSharedCache` object for this subcache
      )doc"_doc
    )
  ;
}
}
