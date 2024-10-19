#include "LIEF/DyldSharedCache/MappingInfo.hpp"
#include "DyldSharedCache/pyDyldSharedCache.hpp"

namespace LIEF::dsc::py {
template<>
void create<dsc::MappingInfo>(nb::module_& m) {
  nb::class_<dsc::MappingInfo> obj(m, "MappingInfo",
    R"doc(
    This class represents a ``dyld_cache_mapping_info`` entry.

    It provides information about the relationshiop between on-disk shared cache
    and in-memory shared cache.
    )doc"_doc
  );

  obj
    .def_prop_ro("address", &dsc::MappingInfo::address,
      R"doc(The in-memory address where this dyld shared cache region is mapped)doc"_doc
    )
    .def_prop_ro("size", &dsc::MappingInfo::size,
      R"doc(Size of the region being mapped)doc"_doc
    )
    .def_prop_ro("end_address", &dsc::MappingInfo::end_address,
      R"doc(End virtual address of the region)doc"_doc
    )
    .def_prop_ro("file_offset", &dsc::MappingInfo::file_offset,
      R"doc(On-disk file offset)doc"_doc
    )
    .def_prop_ro("max_prot", &dsc::MappingInfo::max_prot,
      R"doc(Max memory protection)doc"_doc
    )
    .def_prop_ro("init_prot", &dsc::MappingInfo::init_prot,
      R"doc(Initial memory protection)doc"_doc
    )
  ;
}
}
