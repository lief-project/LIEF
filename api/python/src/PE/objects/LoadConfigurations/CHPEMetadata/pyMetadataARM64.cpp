/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "LIEF/PE/LoadConfigurations/CHPEMetadata/MetadataARM64.hpp"
#include "PE/pyPE.hpp"

#include <string>
#include <sstream>

#include <nanobind/stl/string.h>

#include "pyIterator.hpp"

namespace LIEF::PE::py {

template<>
void create<CHPEMetadataARM64>(nb::module_& m) {
  using namespace LIEF::py;
  nb::class_<CHPEMetadataARM64, CHPEMetadata> meta(m, "CHPEMetadataARM64",
    R"doc(
    This class represents hybrid metadata for ARM64EC or ARM64X.
    )doc"_doc);

  init_ref_iterator<CHPEMetadataARM64::it_range_entries>(meta, "it_range_entries");
  init_ref_iterator<CHPEMetadataARM64::it_redirection_entries>(meta, "it_redirection_entries");

  /* Code range */ {
    using range_entry_t = CHPEMetadataARM64::range_entry_t;
    nb::class_<range_entry_t> range(meta, "range_entry_t",
      "Structure that describes architecture-specific ranges"_doc
    );
    nb::enum_<range_entry_t::TYPE>(range, "TYPE")
      .value("ARM64", range_entry_t::TYPE::ARM64)
      .value("ARM64EC", range_entry_t::TYPE::ARM64EC)
      .value("AMD64", range_entry_t::TYPE::AMD64);

    range
      .def_rw("start_offset", &range_entry_t::start_offset,
        "Raw data (include start RVA and type"_doc
      )
      .def_rw("length", &range_entry_t::length,
        "Range's length"_doc
      )
      .def_prop_ro("type", &range_entry_t::type,
        "Architecture for this range"_doc
      )
      .def_prop_ro("start", &range_entry_t::start,
        "Start of the range (RVA)"_doc
      )
      .def_prop_ro("end", &range_entry_t::end,
        "End of the range (RVA)"_doc
      )
    ;
  }

  /* Redirection Entry */ {
    using redirection_entry_t = CHPEMetadataARM64::redirection_entry_t;
    nb::class_<redirection_entry_t>(meta, "redirection_entry_t",
      "Structure that describes a redirection"_doc
    )
      .def_rw("src", &redirection_entry_t::src)
      .def_rw("dst", &redirection_entry_t::dst)
    ;
  }

  meta
    .def_prop_rw("code_map",
      nb::overload_cast<>(&CHPEMetadataARM64::code_map, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::code_map),
      nb::rv_policy::reference_internal)

    .def_prop_rw("code_map_count",
      nb::overload_cast<>(&CHPEMetadataARM64::code_map_count, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::code_map_count),
      nb::rv_policy::reference_internal)

    .def_prop_rw("code_ranges_to_entrypoints",
      nb::overload_cast<>(&CHPEMetadataARM64::code_ranges_to_entrypoints, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::code_ranges_to_entrypoints),
      nb::rv_policy::reference_internal)

    .def_prop_rw("redirection_metadata",
      nb::overload_cast<>(&CHPEMetadataARM64::redirection_metadata, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::redirection_metadata),
      nb::rv_policy::reference_internal)

    .def_prop_rw("os_arm64x_dispatch_call_no_redirect",
      nb::overload_cast<>(&CHPEMetadataARM64::os_arm64x_dispatch_call_no_redirect, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::os_arm64x_dispatch_call_no_redirect),
      nb::rv_policy::reference_internal)

    .def_prop_rw("os_arm64x_dispatch_ret",
      nb::overload_cast<>(&CHPEMetadataARM64::os_arm64x_dispatch_ret, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::os_arm64x_dispatch_ret),
      nb::rv_policy::reference_internal)

    .def_prop_rw("os_arm64x_dispatch_call",
      nb::overload_cast<>(&CHPEMetadataARM64::os_arm64x_dispatch_call, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::os_arm64x_dispatch_call),
      nb::rv_policy::reference_internal)

    .def_prop_rw("os_arm64x_dispatch_icall",
      nb::overload_cast<>(&CHPEMetadataARM64::os_arm64x_dispatch_icall, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::os_arm64x_dispatch_icall),
      nb::rv_policy::reference_internal)

    .def_prop_rw("os_arm64x_dispatch_icall_cfg",
      nb::overload_cast<>(&CHPEMetadataARM64::os_arm64x_dispatch_icall_cfg, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::os_arm64x_dispatch_icall_cfg),
      nb::rv_policy::reference_internal)

    .def_prop_rw("alternate_entry_point",
      nb::overload_cast<>(&CHPEMetadataARM64::alternate_entry_point, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::alternate_entry_point),
      nb::rv_policy::reference_internal)

    .def_prop_rw("auxiliary_iat",
      nb::overload_cast<>(&CHPEMetadataARM64::auxiliary_iat, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::auxiliary_iat),
      nb::rv_policy::reference_internal)

    .def_prop_rw("code_ranges_to_entry_points_count",
      nb::overload_cast<>(&CHPEMetadataARM64::code_ranges_to_entry_points_count, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::code_ranges_to_entry_points_count),
      nb::rv_policy::reference_internal)

    .def_prop_rw("redirection_metadata_count",
      nb::overload_cast<>(&CHPEMetadataARM64::redirection_metadata_count, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::redirection_metadata_count),
      nb::rv_policy::reference_internal)

    .def_prop_rw("get_x64_information_function_pointer",
      nb::overload_cast<>(&CHPEMetadataARM64::get_x64_information_function_pointer, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::get_x64_information_function_pointer),
      nb::rv_policy::reference_internal)

    .def_prop_rw("set_x64_information_function_pointer",
      nb::overload_cast<>(&CHPEMetadataARM64::set_x64_information_function_pointer, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::set_x64_information_function_pointer),
      nb::rv_policy::reference_internal)

    .def_prop_rw("extra_rfe_table",
      nb::overload_cast<>(&CHPEMetadataARM64::extra_rfe_table, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::extra_rfe_table),
      nb::rv_policy::reference_internal)

   .def_prop_rw("extra_rfe_table_size",
      nb::overload_cast<>(&CHPEMetadataARM64::extra_rfe_table_size, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::extra_rfe_table_size),
      nb::rv_policy::reference_internal)

   .def_prop_rw("os_arm64x_dispatch_fptr",
      nb::overload_cast<>(&CHPEMetadataARM64::os_arm64x_dispatch_fptr, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::os_arm64x_dispatch_fptr),
      nb::rv_policy::reference_internal)

   .def_prop_rw("auxiliary_iat_copy",
      nb::overload_cast<>(&CHPEMetadataARM64::auxiliary_iat_copy, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::auxiliary_iat_copy),
      nb::rv_policy::reference_internal)

   .def_prop_rw("auxiliary_delay_import",
      nb::overload_cast<>(&CHPEMetadataARM64::auxiliary_delay_import, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::auxiliary_delay_import),
      nb::rv_policy::reference_internal)

   .def_prop_rw("auxiliary_delay_import_copy",
      nb::overload_cast<>(&CHPEMetadataARM64::auxiliary_delay_import_copy, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::auxiliary_delay_import_copy),
      nb::rv_policy::reference_internal)

   .def_prop_rw("bitfield_info",
      nb::overload_cast<>(&CHPEMetadataARM64::bitfield_info, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataARM64::bitfield_info),
      nb::rv_policy::reference_internal)

   .def_prop_ro("code_ranges",
      nb::overload_cast<>(&CHPEMetadataARM64::code_ranges),
      nb::rv_policy::reference_internal, nb::keep_alive<0, 1>())

   .def_prop_ro("redirections",
      nb::overload_cast<>(&CHPEMetadataARM64::redirections),
      nb::rv_policy::reference_internal, nb::keep_alive<0, 1>())
  ;

}
}
