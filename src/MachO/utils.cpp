/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#include "LIEF/MachO/utils.hpp"
#include "LIEF/MachO/Structures.hpp"

#include "LIEF/exception.hpp"
#include "LIEF/logging++.hpp"

#include <fstream>
#include <iterator>
#include <string>
#include <stdexcept>
#include <vector>

namespace LIEF {
namespace MachO {

bool is_macho(const std::string& file) {
  std::ifstream binary(file, std::ios::in | std::ios::binary);
  if (not binary) {
    LOG(ERROR) << "Unable to open the '" << file << "'";
    return false;
  }

  MACHO_TYPES magic;
  binary.seekg(0, std::ios::beg);
  binary.read(reinterpret_cast<char*>(&magic), sizeof(uint32_t));

  if (magic == MACHO_TYPES::MH_MAGIC or
      magic == MACHO_TYPES::MH_CIGAM or
      magic == MACHO_TYPES::MH_MAGIC_64 or
      magic == MACHO_TYPES::MH_CIGAM_64 or
      magic == MACHO_TYPES::FAT_MAGIC or
      magic == MACHO_TYPES::FAT_CIGAM)
  {
    return true;
  }
  return false;
}

bool is_macho(const std::vector<uint8_t>& raw) {

  if (raw.size() < sizeof(MACHO_TYPES)) {
    return false;
  }

  MACHO_TYPES magic;

  std::copy(
    reinterpret_cast<const uint8_t*>(raw.data()),
    reinterpret_cast<const uint8_t*>(raw.data()) + sizeof(uint32_t),
    reinterpret_cast<uint8_t*>(&magic));

  if (magic == MACHO_TYPES::MH_MAGIC or
      magic == MACHO_TYPES::MH_CIGAM or
      magic == MACHO_TYPES::MH_MAGIC_64 or
      magic == MACHO_TYPES::MH_CIGAM_64 or
      magic == MACHO_TYPES::FAT_MAGIC or
      magic == MACHO_TYPES::FAT_CIGAM)
  {
    return true;
  }
  return false;
}

bool is_fat(const std::string& file) {
  if (not is_macho(file)) {
    LOG(ERROR) << "'" << file << "' is not a MachO";
    return false;
  }

  std::ifstream binary(file, std::ios::in | std::ios::binary);

  if (not binary) {
    LOG(ERROR) << "Unable to open the '" << file << "'";
    return false;
  }

  MACHO_TYPES magic;
  binary.seekg(0, std::ios::beg);
  binary.read(reinterpret_cast<char*>(&magic), sizeof(uint32_t));

  if (magic == MACHO_TYPES::FAT_MAGIC or
      magic == MACHO_TYPES::FAT_CIGAM)
  {
    return true;
  }

  return false;
}

bool is_64(const std::string& file) {
 if (not is_macho(file)) {
    LOG(ERROR) << "'" << file << "' is not a MachO";
    return false;
  }

  std::ifstream binary(file, std::ios::in | std::ios::binary);

  if (not binary) {
    LOG(ERROR) << "Unable to open the '" << file << "'";
    return false;
  }

  MACHO_TYPES magic;
  binary.seekg(0, std::ios::beg);
  binary.read(reinterpret_cast<char*>(&magic), sizeof(uint32_t));

  if (magic == MACHO_TYPES::MH_MAGIC_64 or
      magic == MACHO_TYPES::MH_CIGAM_64 )
  {
    return true;
  }
  return false;

}


bool check_layout(const Binary& binary, std::string* error) {
  if (binary.has_dyld_info() and not binary.has_segment("__LINKEDIT")) {
    if (error) {
      *error = "No __LINKEDIT segment";
    }
    return false;
  }
  const SegmentCommand& linkedit = *binary.get_segment("__LINKEDIT");
  const DyldInfo& dyld_info      = binary.dyld_info();

  const bool is64 = static_cast<const LIEF::Binary&>(binary).header().is_64();
  uint64_t offset = linkedit.file_offset();

  // Requirement #1: Dyld Info starts at the beginning of __LINKEDIT
  if (dyld_info.rebase().first != 0) {
    if (dyld_info.rebase().first != offset) {
      if (error) {
        *error = "Dyld 'rebase' doesn't start at the begining of LINKEDIT";
      }
      return false;
    }
  }

  else if (dyld_info.bind().first != 0) {
    if (dyld_info.bind().first != offset) {
      if (error) {
        *error = "Dyld 'bind' doesn't start at the begining of LINKEDIT";
      }
      return false;
    }
  }

  else if (dyld_info.export_info().first != 0) {

    if (    dyld_info.export_info().first != offset
        and dyld_info.weak_bind().first   != 0
        and dyld_info.lazy_bind().first   != 0) {

      if (error) {
        *error = "Dyld 'export' doesn't start at the begining of LINKEDIT";
      }
      return false;
    }
  }

  // Update Offset to end of dyld_info contents
  if (dyld_info.export_info().second != 0) {
    offset = dyld_info.export_info().first + dyld_info.export_info().second;
  }

  else if (dyld_info.lazy_bind().second != 0) {
    offset = dyld_info.lazy_bind().first + dyld_info.lazy_bind().second;
  }

  else if (dyld_info.weak_bind().second != 0) {
    offset = dyld_info.weak_bind().first + dyld_info.weak_bind().second;
  }

  else if (dyld_info.bind().second != 0) {
    offset = dyld_info.bind().first + dyld_info.bind().second;
  }

  else if (dyld_info.rebase().second != 0) {
    offset = dyld_info.rebase().first + dyld_info.rebase().second;
  }

  if (not binary.has_dynamic_symbol_command()) {
    if (error) {
      *error = "Dynamic symbol command not found";
    }
    return false;
  }

  // Check Dynamic symbol command consistency
  const DynamicSymbolCommand& dyst = binary.dynamic_symbol_command();


  if (dyst.nb_local_relocations() != 0) {
    if (dyst.local_relocation_offset() != offset) {
      if (error) {
        *error = "Dynamic Symbol command (local relocation offset) out of place";
      }
      return false;
    }
    offset += dyst.nb_local_relocations() * sizeof(relocation_info);
  }

  // Check consistency of Segment Split Info command
  if (binary.has_segment_split_info()) {
    const SegmentSplitInfo& spi = binary.segment_split_info();
    if (spi.data_offset() != 0 and spi.data_offset() != offset) {
      if (error) {
        *error = "Segment Split Info  out of place";
      }
      return false;
    }
    offset += spi.data_size();
  }

  // Check consistency of Function starts
  if (binary.has_function_starts()) {
    const FunctionStarts& fs = binary.function_starts();
    if (fs.data_offset() != 0 and fs.data_offset() != offset) {
      if (error) {
        *error = "Function starts out of place";
      }
      return false;
    }
    offset += fs.data_size();
  }


  // Check consistency of Data in Code
  if (binary.has_data_in_code()) {
    const DataInCode& dic = binary.data_in_code();
    if (dic.data_offset() != offset) {
      if (error) {
        *error = "Data in Code out of place";
      }
      return false;
    }
    offset += dic.data_size();
  }

  // Check consistency of Code Signature
  if (binary.has_code_signature()) {
    const CodeSignature& cs = binary.code_signature();
    if (cs.data_offset() != offset) {
      if (error) {
        *error = "Code signature out of place";
      }
      return false;
    }
    offset += cs.data_size();
  }

  // {
  //    TODO: Linker optimization hit
  // }

  if (not binary.has_symbol_command()) {
    if (error) {
      *error = "Symbol command not found";
    }
    return false;
  }

  const SymbolCommand& st = binary.symbol_command();
  if (st.numberof_symbols() != 0) {
    // Check offset
    if (st.symbol_offset() != offset) {
      if (error) {
        *error = "Symbol table out of place";
      }
      return false;
    }
    offset += st.numberof_symbols() * (is64 ? sizeof(nlist_64) : sizeof(nlist_32));
  }

  size_t isym = 0;

  if (dyst.nb_local_symbols() != 0) {
    // Check index match
    if (isym != dyst.idx_local_symbol()) {
      if (error) {
        *error = "Dynamic Symbol command (idx_local_symbol) out of place";
      }
      return false;
    }
    isym += dyst.nb_local_symbols();
  }


  if (dyst.nb_external_define_symbols() != 0) {
    // Check index match
    if (isym != dyst.idx_external_define_symbol()) {
      if (error) {
        *error = "Dynamic Symbol command (idx_external_define_symbol) out of place";
      }
      return false;
    }
    isym += dyst.nb_external_define_symbols();
  }

  if (dyst.nb_undefined_symbols() != 0) {
    // Check index match
    if (isym != dyst.idx_undefined_symbol()) {
      if (error) {
        *error = "Dynamic Symbol command (idx_undefined_symbol) out of place";
      }
      return false;
    }
    isym += dyst.nb_undefined_symbols();
  }

  // {
  //    TODO: twolevel_hint
  // }


  if (dyst.nb_external_relocations() != 0) {
    if (dyst.external_relocation_offset() != offset) {
      if (error) {
        *error = "Dynamic Symbol command (external_relocation_offset) out of place";
      }
      return false;
    }

    offset += dyst.nb_external_relocations() * sizeof(relocation_info);
  }


  if (dyst.nb_indirect_symbols() != 0) {
    if (dyst.indirect_symbol_offset() != offset) {
      if (error) {
        *error = "Dynamic Symbol command (indirect_symbol_offset) out of place";
      }
      return false;
    }

    offset += dyst.nb_indirect_symbols() * sizeof(uint32_t);
  }

  uint64_t rounded_offset = offset;
  uint64_t input_indirectsym_pad = 0;
  if (is64 and (dyst.nb_indirect_symbols() % 2) != 0) {
    const uint32_t align = offset % 8;
    if (align) {
      rounded_offset = offset - align;
    }
  }

  if (dyst.toc_offset() != 0) {
    if (dyst.toc_offset() != offset and dyst.toc_offset() != rounded_offset) {
      if (error) {
        *error = "Dynamic Symbol command (toc_offset) out of place";
      }
      return false;
    }
    if (dyst.toc_offset() == offset) {
      offset        += dyst.nb_toc() * sizeof(dylib_table_of_contents);
      rounded_offset = offset;
    }
    else if (dyst.toc_offset() == rounded_offset) {
      input_indirectsym_pad = rounded_offset - offset;

      rounded_offset += dyst.nb_toc() * sizeof(dylib_table_of_contents);
      offset          = rounded_offset;
    }
  }


  if (dyst.nb_module_table() != 0) {
    if (dyst.module_table_offset() != offset and dyst.module_table_offset() != rounded_offset) {
      if (error) {
        *error = "Dynamic Symbol command (module_table_offset) out of place";
      }
      return false;
    }

    if (is64) {
      if (dyst.module_table_offset() == offset) {
        offset        += dyst.nb_module_table() * sizeof(dylib_module_64);
        rounded_offset = offset;
      }
      else if (dyst.module_table_offset() == rounded_offset) {
        input_indirectsym_pad = rounded_offset - offset;
        rounded_offset += dyst.nb_module_table() * sizeof(dylib_module_64);
        offset         = rounded_offset;
      }
    } else {
      offset        += dyst.nb_module_table() * sizeof(dylib_module_32);
      rounded_offset = offset;
    }
  }


  if (dyst.nb_external_reference_symbols() != 0) {
    if (dyst.external_reference_symbol_offset() != offset and dyst.external_reference_symbol_offset() != rounded_offset) {
      if (error) {
        *error = "Dynamic Symbol command (external_reference_symbol_offset) out of place";
      }
      return false;
    }

    if (dyst.external_reference_symbol_offset() == offset) {
      offset        += dyst.nb_external_reference_symbols() * sizeof(dylib_reference);
      rounded_offset = offset;
    }
    else if (dyst.external_reference_symbol_offset() == rounded_offset) {
      input_indirectsym_pad = rounded_offset - offset;
      rounded_offset += dyst.nb_external_reference_symbols() * sizeof(dylib_reference);
      offset         = rounded_offset;
    }
  }


  if (st.strings_size() != 0) {
    if (st.strings_offset() != offset and st.strings_offset() != rounded_offset) {
      if (error) {
        *error = "Symbol command (strings_offset) out of place";
      }
      return false;
    }


    if (st.strings_offset() == offset) {
      offset        += st.strings_size();
      rounded_offset = offset;
    }
    else if (st.strings_offset() == rounded_offset) {
      input_indirectsym_pad = rounded_offset - offset;
      rounded_offset += st.strings_size();
      offset         = rounded_offset;
    }
  }

  // {
  //    TODO: Code Signature
  // }

  const uint64_t object_size = linkedit.file_offset() + linkedit.file_size();
  if (offset != object_size and rounded_offset != object_size) {
    if (error) {
      *error = "link edit info doesn't fill the __LINKEDIT segment";
    }
    return false;
  }
  return true;
}

}
}

