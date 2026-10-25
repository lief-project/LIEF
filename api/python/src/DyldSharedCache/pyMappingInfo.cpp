#include "DyldSharedCache/pyDyldSharedCache.hpp"
#include "LIEF/DyldSharedCache/MappingInfo.hpp"

namespace LIEF::dsc::py {
template<>
void create<dsc::MappingInfo>(nb::module_& m) {
  nb::class_<dsc::MappingInfo> obj(
      m, "MappingInfo",
      R"doc(
      This class represents a ``dyld_cache_mapping_info`` entry.

      It provides information about the relationship between on-disk shared cache
      and in-memory shared cache.
      )doc"_doc
  );

  obj.def_prop_ro(
         "address", &dsc::MappingInfo::address,
         "The in-memory address where this dyld shared cache region is mapped"_doc
  )
      .def_prop_ro("size", &dsc::MappingInfo::size,
                   "Size of the region being mapped"_doc)
      .def_prop_ro("end_address", &dsc::MappingInfo::end_address,
                   "End virtual address of the region"_doc)
      .def_prop_ro("file_offset", &dsc::MappingInfo::file_offset,
                   "On-disk file offset"_doc)
      .def_prop_ro("max_prot", &dsc::MappingInfo::max_prot,
                   "Max memory protection"_doc)
      .def_prop_ro("init_prot", &dsc::MappingInfo::init_prot,
                   "Initial memory protection"_doc);
}
}
