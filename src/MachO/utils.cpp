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

#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "LIEF/MachO/utils.hpp"
#include "LIEF/MachO/DynamicSymbolCommand.hpp"
#include "LIEF/MachO/SegmentSplitInfo.hpp"
#include "LIEF/MachO/DyldInfo.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"
#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/SymbolCommand.hpp"
#include "LIEF/MachO/DataInCode.hpp"
#include "LIEF/MachO/FunctionStarts.hpp"
#include "LIEF/MachO/CodeSignature.hpp"
#include "MachO/Structures.hpp"

#include "LIEF/exception.hpp"
#include "LIEF/BinaryStream/FileStream.hpp"
#include "LIEF/BinaryStream/SpanStream.hpp"
#include "logging.hpp"


namespace LIEF {
namespace MachO {

inline result<MACHO_TYPES> magic_from_stream(BinaryStream& stream) {
  stream.setpos(0);
  if (auto magic_res = stream.read<uint32_t>()) {
    return static_cast<MACHO_TYPES>(*magic_res);
  }
  return make_error_code(lief_errors::read_error);
}

inline bool is_macho(BinaryStream& stream) {
  if (auto magic_res = magic_from_stream(stream)) {
    const MACHO_TYPES magic = *magic_res;
    return (magic == MACHO_TYPES::MH_MAGIC ||
            magic == MACHO_TYPES::MH_CIGAM ||
            magic == MACHO_TYPES::MH_MAGIC_64 ||
            magic == MACHO_TYPES::MH_CIGAM_64 ||
            magic == MACHO_TYPES::FAT_MAGIC ||
            magic == MACHO_TYPES::FAT_CIGAM);
  }
  return false;
}

bool is_macho(const std::string& file) {
  if (auto stream = FileStream::from_file(file)) {
    return is_macho(*stream);
  }
  return false;
}

bool is_macho(const std::vector<uint8_t>& raw) {
  if (auto stream = SpanStream::from_vector(raw)) {
    return is_macho(*stream);
  }
  return false;
}

bool is_fat(const std::string& file) {
  if (auto stream = FileStream::from_file(file)) {
    if (auto magic_res = magic_from_stream(*stream)) {
      const MACHO_TYPES magic = *magic_res;
      return magic == MACHO_TYPES::FAT_MAGIC ||
             magic == MACHO_TYPES::FAT_CIGAM;
    }
  }
  return false;
}

bool is_64(const std::string& file) {
  if (auto stream = FileStream::from_file(file)) {
    if (auto magic_res = magic_from_stream(*stream)) {
      const MACHO_TYPES magic = *magic_res;
      return magic == MACHO_TYPES::MH_MAGIC_64 ||
             magic == MACHO_TYPES::MH_CIGAM_64;
    }
  }
  return false;
}


bool check_layout(const Binary& binary, std::string* error) {
  const SegmentCommand* linkedit = binary.get_segment("__LINKEDIT");
  const DyldInfo* dyld_info      = binary.dyld_info();

  if (dyld_info == nullptr && linkedit == nullptr) {
    LIEF_WARN("No __LINKEDIT segment neither Dyld info");
    return false;
  }

  if (dyld_info != nullptr && linkedit == nullptr) {
    if (error != nullptr) {
      *error = "No __LINKEDIT segment";
    }
    return false;
  }


  const bool is64 = static_cast<const LIEF::Binary&>(binary).header().is_64();
  uint64_t offset = linkedit->file_offset();

  // Requirement #1: Dyld Info starts at the beginning of __LINKEDIT
  if (dyld_info->rebase().first != 0) {
    if (dyld_info->rebase().first != offset) {
      if (error != nullptr) {
        *error = "Dyld 'rebase' doesn't start at the begining of LINKEDIT";
      }
      return false;
    }
  }

  else if (dyld_info->bind().first != 0) {
    if (dyld_info->bind().first != offset) {
      if (error != nullptr) {
        *error = "Dyld 'bind' doesn't start at the begining of LINKEDIT";
      }
      return false;
    }
  }

  else if (dyld_info->export_info().first != 0) {

    if (dyld_info->export_info().first != offset &&
        dyld_info->weak_bind().first   != 0      &&
        dyld_info->lazy_bind().first   != 0      )
    {
      if (error != nullptr) {
        *error = "Dyld 'export' doesn't start at the begining of LINKEDIT";
      }
      return false;
    }
  }

  // Update Offset to end of dyld_info->contents
  if (dyld_info->export_info().second != 0) {
    offset = dyld_info->export_info().first + dyld_info->export_info().second;
  }

  else if (dyld_info->lazy_bind().second != 0) {
    offset = dyld_info->lazy_bind().first + dyld_info->lazy_bind().second;
  }

  else if (dyld_info->weak_bind().second != 0) {
    offset = dyld_info->weak_bind().first + dyld_info->weak_bind().second;
  }

  else if (dyld_info->bind().second != 0) {
    offset = dyld_info->bind().first + dyld_info->bind().second;
  }

  else if (dyld_info->rebase().second != 0) {
    offset = dyld_info->rebase().first + dyld_info->rebase().second;
  }

  const DynamicSymbolCommand* dyst = binary.dynamic_symbol_command();
  if (dyst == nullptr) {
    if (error != nullptr) {
      *error = "Dynamic symbol command not found";
    }
    return false;
  }

  // Check Dynamic symbol command consistency


  if (dyst->nb_local_relocations() != 0) {
    if (dyst->local_relocation_offset() != offset) {
      if (error != nullptr) {
        *error = "Dynamic Symbol command (local relocation offset) out of place";
      }
      return false;
    }
    offset += dyst->nb_local_relocations() * sizeof(details::relocation_info);
  }

  // Check consistency of Segment Split Info command
  const SegmentSplitInfo* spi = binary.segment_split_info();
  if (spi != nullptr) {
    if (spi->data_offset() != 0 && spi->data_offset() != offset) {
      if (error != nullptr) {
        *error = "Segment Split Info out of place";
      }
      return false;
    }
    offset += spi->data_size();
  }

  // Check consistency of Function starts
  const FunctionStarts* fs = binary.function_starts();
  if (fs != nullptr) {
    if (fs->data_offset() != 0 && fs->data_offset() != offset) {
      if (error != nullptr) {
        *error = "Function starts out of place";
      }
      return false;
    }
    offset += fs->data_size();
  }


  // Check consistency of Data in Code
  const DataInCode* dic = binary.data_in_code();
  if (dic != nullptr) {
    if (dic->data_offset() != offset) {
      if (error != nullptr) {
        *error = "Data in Code out of place";
      }
      return false;
    }
    offset += dic->data_size();
  }

  // Check consistency of Code Signature
  const CodeSignature* cs = binary.code_signature();
  if (cs != nullptr) {
    if (cs->data_offset() != offset) {
      if (error != nullptr) {
        *error = "Code signature out of place";
      }
      return false;
    }
    offset += cs->data_size();
  }

  // {
  //    TODO: Linker optimization hit
  // }

  const SymbolCommand* st = binary.symbol_command();
  if (st == nullptr) {
    if (error != nullptr) {
      *error = "Symbol command !found";
    }
    return false;
  }

  if (st->numberof_symbols() != 0) {
    // Check offset
    if (st->symbol_offset() != offset) {
      if (error != nullptr) {
        *error = "Symbol table out of place";
      }
      return false;
    }
    offset += st->numberof_symbols() * (is64 ? sizeof(details::nlist_64) : sizeof(details::nlist_32));
  }

  size_t isym = 0;

  if (dyst->nb_local_symbols() != 0) {
    // Check index match
    if (isym != dyst->idx_local_symbol()) {
      if (error != nullptr) {
        *error = "Dynamic Symbol command (idx_local_symbol) out of place";
      }
      return false;
    }
    isym += dyst->nb_local_symbols();
  }


  if (dyst->nb_external_define_symbols() != 0) {
    // Check index match
    if (isym != dyst->idx_external_define_symbol()) {
      if (error != nullptr) {
        *error = "Dynamic Symbol command (idx_external_define_symbol) out of place";
      }
      return false;
    }
    isym += dyst->nb_external_define_symbols();
  }

  if (dyst->nb_undefined_symbols() != 0) {
    // Check index match
    if (isym != dyst->idx_undefined_symbol()) {
      if (error != nullptr) {
        *error = "Dynamic Symbol command (idx_undefined_symbol) out of place";
      }
      return false;
    }
    isym += dyst->nb_undefined_symbols();
  }

  // {
  //    TODO: twolevel_hint
  // }


  if (dyst->nb_external_relocations() != 0) {
    if (dyst->external_relocation_offset() != offset) {
      if (error != nullptr) {
        *error = "Dynamic Symbol command (external_relocation_offset) out of place";
      }
      return false;
    }

    offset += dyst->nb_external_relocations() * sizeof(details::relocation_info);
  }


  if (dyst->nb_indirect_symbols() != 0) {
    if (dyst->indirect_symbol_offset() != offset) {
      if (error != nullptr) {
        *error = "Dynamic Symbol command (indirect_symbol_offset) out of place";
      }
      return false;
    }

    offset += dyst->nb_indirect_symbols() * sizeof(uint32_t);
  }

  uint64_t rounded_offset = offset;
  uint64_t input_indirectsym_pad = 0;
  if (is64 && (dyst->nb_indirect_symbols() % 2) != 0) {
    const uint32_t align = offset % 8;
    if (align != 0u) {
      rounded_offset = offset - align;
    }
  }

  if (dyst->toc_offset() != 0) {
    if (dyst->toc_offset() != offset && dyst->toc_offset() != rounded_offset) {
      if (error != nullptr) {
        *error = "Dynamic Symbol command (toc_offset) out of place";
      }
      return false;
    }
    if (dyst->toc_offset() == offset) {
      offset        += dyst->nb_toc() * sizeof(details::dylib_table_of_contents);
      rounded_offset = offset;
    }
    else if (dyst->toc_offset() == rounded_offset) {
      input_indirectsym_pad = rounded_offset - offset;

      rounded_offset += dyst->nb_toc() * sizeof(details::dylib_table_of_contents);
      offset          = rounded_offset;
    }
  }


  if (dyst->nb_module_table() != 0) {
    if (dyst->module_table_offset() != offset && dyst->module_table_offset() != rounded_offset) {
      if (error != nullptr) {
        *error = "Dynamic Symbol command (module_table_offset) out of place";
      }
      return false;
    }

    if (is64) {
      if (dyst->module_table_offset() == offset) {
        offset        += dyst->nb_module_table() * sizeof(details::dylib_module_64);
        rounded_offset = offset;
      }
      else if (dyst->module_table_offset() == rounded_offset) {
        input_indirectsym_pad = rounded_offset - offset;
        rounded_offset += dyst->nb_module_table() * sizeof(details::dylib_module_64);
        offset         = rounded_offset;
      }
    } else {
      offset        += dyst->nb_module_table() * sizeof(details::dylib_module_32);
      rounded_offset = offset;
    }
  }


  if (dyst->nb_external_reference_symbols() != 0) {
    if (dyst->external_reference_symbol_offset() != offset && dyst->external_reference_symbol_offset() != rounded_offset) {
      if (error != nullptr) {
        *error = "Dynamic Symbol command (external_reference_symbol_offset) out of place";
      }
      return false;
    }

    if (dyst->external_reference_symbol_offset() == offset) {
      offset        += dyst->nb_external_reference_symbols() * sizeof(details::dylib_reference);
      rounded_offset = offset;
    }
    else if (dyst->external_reference_symbol_offset() == rounded_offset) {
      input_indirectsym_pad = rounded_offset - offset;
      rounded_offset += dyst->nb_external_reference_symbols() * sizeof(details::dylib_reference);
      offset         = rounded_offset;
    }
  }


  if (st->strings_size() != 0) {
    if (st->strings_offset() != offset && st->strings_offset() != rounded_offset) {
      if (error != nullptr) {
        *error = "Symbol command (strings_offset) out of place";
      }
      return false;
    }


    if (st->strings_offset() == offset) {
      offset        += st->strings_size();
      rounded_offset = offset;
    }
    else if (st->strings_offset() == rounded_offset) {
      input_indirectsym_pad = rounded_offset - offset;
      rounded_offset += st->strings_size();
      offset         = rounded_offset;
    }
  }

  // {
  //    TODO: Code Signature
  // }
  LIEF_DEBUG("input_indirectsym_pad: {:x}", input_indirectsym_pad);
  const uint64_t object_size = linkedit->file_offset() + linkedit->file_size();
  if (offset != object_size && rounded_offset != object_size) {
    if (error != nullptr) {
      *error = "link edit info doesn't fill the __LINKEDIT segment";
    }
    return false;
  }
  return true;
}

}
}

