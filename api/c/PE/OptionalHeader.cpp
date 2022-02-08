/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include "OptionalHeader.hpp"

namespace LIEF {
namespace PE {

void init_c_optional_header(Pe_Binary_t* c_binary, Binary* binary) {

  const OptionalHeader& optional_header = binary->optional_header();
  c_binary->optional_header.magic                          = static_cast<enum LIEF_PE_PE_TYPES>(optional_header.magic());
  c_binary->optional_header.major_linker_version           = optional_header.major_linker_version();
  c_binary->optional_header.minor_linker_version           = optional_header.minor_linker_version();
  c_binary->optional_header.sizeof_code                    = optional_header.sizeof_code();
  c_binary->optional_header.sizeof_initialized_data        = optional_header.sizeof_initialized_data();
  c_binary->optional_header.sizeof_uninitialized_data      = optional_header.sizeof_uninitialized_data();
  c_binary->optional_header.addressof_entrypoint           = optional_header.addressof_entrypoint();
  c_binary->optional_header.baseof_code                    = optional_header.baseof_code();
  if (optional_header.magic() == PE_TYPE::PE32) {
    c_binary->optional_header.baseof_data                  = optional_header.baseof_data();
  } else {
    c_binary->optional_header.baseof_data                  = 0;
  }
  c_binary->optional_header.imagebase                      = optional_header.imagebase();
  c_binary->optional_header.section_alignment              = optional_header.section_alignment();
  c_binary->optional_header.file_alignment                 = optional_header.file_alignment();
  c_binary->optional_header.major_operating_system_version = optional_header.major_operating_system_version();
  c_binary->optional_header.minor_operating_system_version = optional_header.minor_operating_system_version();
  c_binary->optional_header.major_image_version            = optional_header.major_image_version();
  c_binary->optional_header.minor_image_version            = optional_header.minor_image_version();
  c_binary->optional_header.major_subsystem_version        = optional_header.major_subsystem_version();
  c_binary->optional_header.minor_subsystem_version        = optional_header.minor_subsystem_version();
  c_binary->optional_header.win32_version_value            = optional_header.win32_version_value();
  c_binary->optional_header.sizeof_image                   = optional_header.sizeof_image();
  c_binary->optional_header.sizeof_headers                 = optional_header.sizeof_headers();
  c_binary->optional_header.checksum                       = optional_header.checksum();
  c_binary->optional_header.subsystem                      = static_cast<enum LIEF_PE_SUBSYSTEM>(optional_header.subsystem());
  c_binary->optional_header.dll_characteristics            = optional_header.dll_characteristics();
  c_binary->optional_header.sizeof_stack_reserve           = optional_header.sizeof_stack_reserve();
  c_binary->optional_header.sizeof_stack_commit            = optional_header.sizeof_stack_commit();
  c_binary->optional_header.sizeof_heap_reserve            = optional_header.sizeof_heap_reserve();
  c_binary->optional_header.sizeof_heap_commit             = optional_header.sizeof_heap_commit();
  c_binary->optional_header.loader_flags                   = optional_header.loader_flags();
  c_binary->optional_header.numberof_rva_and_size          = optional_header.numberof_rva_and_size();
}

}
}
