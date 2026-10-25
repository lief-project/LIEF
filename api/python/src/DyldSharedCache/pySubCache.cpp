#include "DyldSharedCache/pyDyldSharedCache.hpp"
#include "LIEF/DyldSharedCache/DyldSharedCache.hpp"
#include "LIEF/DyldSharedCache/SubCache.hpp"

#include <nanobind/stl/array.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::dsc::py {
template<>
void create<dsc::SubCache>(nb::module_& m) {
  nb::class_<dsc::SubCache> obj(
      m, "SubCache",
      R"doc(
      This class represents a subcache in the case of large/split dyld shared
      cache.

      It mirror (and abstracts) the original ``dyld_subcache_entry`` / ``dyld_subcache_entry_v1``
      )doc"_doc
  );

  obj.def_prop_ro("uuid", &SubCache::uuid, "The uuid of the subcache file"_doc)
      .def_prop_ro(
          "vm_offset", &SubCache::vm_offset,
          "The offset of this subcache from the main cache base address"_doc
      )
      .def_prop_ro("suffix", &SubCache::suffix,
                   R"doc(
                   The file name suffix of the subCache file
                   (e.g. ``.25.data``, ``.03.development``)
                   )doc"_doc)
      .def_prop_ro(
          "cache",
          [](const SubCache& self) {
            return std::unique_ptr<DyldSharedCache>(
                const_cast<DyldSharedCache*>(self.cache().release())
            );
          },
          "The associated :class:`~.DyldSharedCache` object for this subcache"_doc,
          nb::keep_alive<0, 1>()
      );
}
}
