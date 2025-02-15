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
#include "LIEF/PE/LoadConfigurations/CHPEMetadata/MetadataX86.hpp"
#include "PE/pyPE.hpp"

#include <string>
#include <sstream>

#include <nanobind/stl/string.h>
#include "nanobind/extra/stl/lief_optional.h"

namespace LIEF::PE::py {

template<>
void create<CHPEMetadataX86>(nb::module_& m) {
  nb::class_<CHPEMetadataX86, CHPEMetadata> meta(m, "CHPEMetadataX86",
    R"doc(
    This class represents hybrid metadata for X86.
    )doc"_doc);

  meta
    .def_prop_rw("chpe_code_address_range_offset",
      nb::overload_cast<>(&CHPEMetadataX86::chpe_code_address_range_offset, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataX86::chpe_code_address_range_offset),
      nb::rv_policy::reference_internal)

    .def_prop_rw("chpe_code_address_range_count",
      nb::overload_cast<>(&CHPEMetadataX86::chpe_code_address_range_count, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataX86::chpe_code_address_range_count),
      nb::rv_policy::reference_internal)

    .def_prop_rw("wowa64_exception_handler_function_pointer",
      nb::overload_cast<>(&CHPEMetadataX86::wowa64_exception_handler_function_pointer, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataX86::wowa64_exception_handler_function_pointer),
      nb::rv_policy::reference_internal)

    .def_prop_rw("wowa64_dispatch_call_function_pointer",
      nb::overload_cast<>(&CHPEMetadataX86::wowa64_dispatch_call_function_pointer, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataX86::wowa64_dispatch_call_function_pointer),
      nb::rv_policy::reference_internal)

    .def_prop_rw("wowa64_dispatch_indirect_call_function_pointer",
      nb::overload_cast<>(&CHPEMetadataX86::wowa64_dispatch_indirect_call_function_pointer, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataX86::wowa64_dispatch_indirect_call_function_pointer),
      nb::rv_policy::reference_internal)

    .def_prop_rw("wowa64_dispatch_indirect_call_cfg_function_pointer",
      nb::overload_cast<>(&CHPEMetadataX86::wowa64_dispatch_indirect_call_cfg_function_pointer, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataX86::wowa64_dispatch_indirect_call_cfg_function_pointer),
      nb::rv_policy::reference_internal)

    .def_prop_rw("wowa64_dispatch_ret_function_pointer",
      nb::overload_cast<>(&CHPEMetadataX86::wowa64_dispatch_ret_function_pointer, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataX86::wowa64_dispatch_ret_function_pointer),
      nb::rv_policy::reference_internal)

    .def_prop_rw("wowa64_dispatch_ret_leaf_function_pointer",
      nb::overload_cast<>(&CHPEMetadataX86::wowa64_dispatch_ret_leaf_function_pointer, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataX86::wowa64_dispatch_ret_leaf_function_pointer),
      nb::rv_policy::reference_internal)

    .def_prop_rw("wowa64_dispatch_jump_function_pointer",
      nb::overload_cast<>(&CHPEMetadataX86::wowa64_dispatch_jump_function_pointer, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataX86::wowa64_dispatch_jump_function_pointer),
      nb::rv_policy::reference_internal)

    .def_prop_rw("compiler_iat_pointer",
      nb::overload_cast<>(&CHPEMetadataX86::compiler_iat_pointer, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataX86::compiler_iat_pointer),
      nb::rv_policy::reference_internal)

    .def_prop_rw("wowa64_rdtsc_function_pointer",
      nb::overload_cast<>(&CHPEMetadataX86::wowa64_rdtsc_function_pointer, nb::const_),
      nb::overload_cast<uint32_t>(&CHPEMetadataX86::wowa64_rdtsc_function_pointer),
      nb::rv_policy::reference_internal)
  ;
}
}
