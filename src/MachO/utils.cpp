/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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

#include <string>
#include <vector>

#include "LIEF/MachO/FatBinary.hpp"
#include "LIEF/MachO/utils.hpp"
#include "LIEF/MachO/DynamicSymbolCommand.hpp"
#include "LIEF/MachO/SegmentSplitInfo.hpp"
#include "LIEF/MachO/DyldInfo.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"
#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/SymbolCommand.hpp"
#include "LIEF/MachO/DataInCode.hpp"
#include "LIEF/MachO/DyldChainedFixups.hpp"
#include "LIEF/MachO/DyldExportsTrie.hpp"
#include "LIEF/MachO/DylibCommand.hpp"
#include "LIEF/MachO/FunctionStarts.hpp"
#include "LIEF/MachO/CodeSignature.hpp"
#include "LIEF/MachO/CodeSignatureDir.hpp"
#include "LIEF/MachO/LinkerOptHint.hpp"
#include "LIEF/MachO/TwoLevelHints.hpp"
#include "LIEF/utils.hpp"

#include "Object.tcc"

#include "MachO/Structures.hpp"


#include "LIEF/BinaryStream/FileStream.hpp"
#include "LIEF/BinaryStream/SpanStream.hpp"
#include "logging.hpp"


namespace LIEF {
namespace MachO {

inline result<MACHO_TYPES> magic_from_stream(BinaryStream& stream) {
  ScopedStream scoped(stream, 0);
  if (auto magic_res = scoped->read<uint32_t>()) {
    return static_cast<MACHO_TYPES>(*magic_res);
  }
  return make_error_code(lief_errors::read_error);
}

bool is_macho(BinaryStream& stream) {
  if (auto magic_res = magic_from_stream(stream)) {
    const MACHO_TYPES magic = *magic_res;
    return (magic == MACHO_TYPES::MH_MAGIC ||
            magic == MACHO_TYPES::MH_CIGAM ||
            magic == MACHO_TYPES::MH_MAGIC_64 ||
            magic == MACHO_TYPES::MH_CIGAM_64 ||
            magic == MACHO_TYPES::FAT_MAGIC ||
            magic == MACHO_TYPES::FAT_CIGAM ||
            magic == MACHO_TYPES::NEURAL_MODEL);
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


bool check_layout(const FatBinary& fat, std::string* error) {
  bool is_ok = true;
  for (Binary& bin : fat) {
    std::string out;
    if (!check_layout(bin, &out)) {
      is_ok = false;
      if (error) { *error += out + '\n'; }
    }
  }
  return is_ok;
}

// Return true if segments overlap
bool check_overlapping(const Binary& binary, std::string* error) {
  for (const SegmentCommand& lhs : binary.segments()) {
    const uint64_t lhs_vm_end   = lhs.virtual_address() + lhs.virtual_size();
    const uint64_t lhs_file_end = lhs.file_offset() + lhs.file_size();
    for (const SegmentCommand& rhs : binary.segments()) {
      if (lhs.index() == rhs.index()) {
        continue;
      }
      const uint64_t rhs_vm_end   = rhs.virtual_address() + rhs.virtual_size();
      const uint64_t rhs_file_end = rhs.file_offset() + rhs.file_size();

      const bool vm_overalp = (rhs.virtual_address() <= lhs.virtual_address() && rhs_vm_end > lhs.virtual_address() && lhs_vm_end > lhs.virtual_address()) ||
                              (rhs.virtual_address() >= lhs.virtual_address()  && rhs.virtual_address() < lhs_vm_end && rhs_vm_end > rhs.virtual_address());
      if (vm_overalp) {
        if (error) {
          *error = fmt::format(R"delim(
          Segments '{}' and '{}' overlap (virtual addresses):
            [0x{:08x}, 0x{:08x}] [0x{:08x}, 0x{:08x}]
          )delim", lhs.name(), rhs.name(),
          lhs.virtual_address(), lhs_vm_end, rhs.virtual_address(), rhs_vm_end);
          return true;
        }
      }
      const bool file_overlap = (rhs.file_offset() <= lhs.file_offset() && rhs_file_end > lhs.file_offset() && lhs_file_end > lhs.file_offset()) ||
                                (rhs.file_offset() >= lhs.file_offset()  && rhs.file_offset() < lhs_file_end && rhs_file_end > rhs.file_offset());
      if (file_overlap) {
        if (error) {
          *error = fmt::format(R"delim(
          Segments '{}' and '{}' overlap (file offsets):
            [0x{:08x}, 0x{:08x}] [0x{:08x}, 0x{:08x}]
          )delim", lhs.name(), rhs.name(),
          lhs.file_offset(), lhs_file_end, rhs.file_offset(), rhs_file_end);
          return true;
        }
      }

      if (lhs.index() < rhs.index()) {

        const bool wrong_order = lhs.virtual_address() > rhs.virtual_address() ||
                                 (lhs.file_offset() > rhs.file_offset() && lhs.file_offset() != 0 && rhs.file_offset() != 0);
        if (wrong_order) {
          if (error) {
            *error = fmt::format(R"delim(
            Segments '{}' and '{}' are wrongly ordered
            )delim", lhs.name(), rhs.name());
            return true;
          }
        }
      }
    }
  }
  return false;
}



inline uint64_t rnd64(uint64_t v, uint64_t r) {
  r--;
  v += r;
  v &= ~static_cast<int64_t>(r);
  return v;
}

inline uint64_t rnd(uint64_t v, uint64_t r) {
  return rnd64(v, r);
}

// Mirror of MachOAnalyzer::validEmbeddedPaths
bool check_valid_paths(const Binary& binary, std::string* error) {
  bool has_install_name = false;
  int dependents_count  = 0;
  for (const LoadCommand& cmd : binary.commands()) {
    switch (cmd.command()) {
      case LoadCommand::TYPE::ID_DYLIB:
        {
          has_install_name = true;
          [[fallthrough]];
        }
      case LoadCommand::TYPE::LOAD_DYLIB:
      case LoadCommand::TYPE::LOAD_WEAK_DYLIB:
      case LoadCommand::TYPE::REEXPORT_DYLIB:
      case LoadCommand::TYPE::LOAD_UPWARD_DYLIB:
        {
          if (!DylibCommand::classof(&cmd)) {
            LIEF_ERR("{} is not associated with a DylibCommand which should be the case",
                     to_string(cmd.command()));
            break;
          }
          auto& dylib = *cmd.as<DylibCommand>();
          if (dylib.command() != LoadCommand::TYPE::ID_DYLIB) {
            ++dependents_count;
          }
          break;
        }
      default: {}
    }
  }

  const Header::FILE_TYPE ftype = binary.header().file_type();
  if (ftype == Header::FILE_TYPE::DYLIB) {
    if (!has_install_name) {
      if (error) {
        *error = fmt::format(R"delim(
        Missing a LC_ID_DYLIB command for a MH_DYLIB file
        )delim");
      }
      return false;
    }
  } else {
    if (has_install_name) {
      if (error) {
        *error = fmt::format(R"delim(
        LC_ID_DYLIB command found in a non MH_DYLIB file
        )delim");
      }
      return false;
    }
  }
  const bool is_dynamic_exe =
    ftype == Header::FILE_TYPE::EXECUTE && binary.has(LoadCommand::TYPE::LOAD_DYLINKER);
  if (dependents_count == 0 && is_dynamic_exe) {
      if (error) {
        *error = fmt::format(R"delim(
        Missing libraries. It must link with at least one library (like libSystem.dylib)
        )delim");
      }
      return false;
  }
  return true;
}

bool check_layout(const Binary& binary, std::string* error) {
  if (check_overlapping(binary, error)) {
    return false;
  }

  if (!check_valid_paths(binary, error)) {
    return false;
  }

  const SegmentCommand* linkedit = binary.get_segment("__LINKEDIT");
  if (linkedit == nullptr) {
    *error = "Missing __LINKEDIT segment";
    return false;
  }

  const bool is64 = static_cast<const LIEF::Binary&>(binary).header().is_64();
  uint64_t offset = linkedit->file_offset();

  if (const DyldInfo* dyld_info = binary.dyld_info()) {
    if (dyld_info->rebase().first != 0) {
      if (dyld_info->rebase().first != offset) {
        if (error != nullptr) {
          *error = fmt::format(R"delim(
          __LINKEDIT does not start with LC_DYLD_INFO.rebase:
            Expecting offset: 0x{:x} while it is 0x{:x}
          )delim", offset, dyld_info->rebase().first);
        }
        return false;
      }
    }

    else if (dyld_info->bind().first != 0) {
      if (dyld_info->bind().first != offset) {
        if (error != nullptr) {
          *error = fmt::format(R"delim(
          __LINKEDIT does not start with LC_DYLD_INFO.bind:
            Expecting offset: 0x{:x} while it is 0x{:x}
          )delim", offset, dyld_info->bind().first);
        }
        return false;
      }
    }

    else if (dyld_info->export_info().first != 0) {
      if (dyld_info->export_info().first != offset &&
          dyld_info->weak_bind().first   != 0      &&
          dyld_info->lazy_bind().first   != 0         ) {
        if (error != nullptr) {
          *error = fmt::format(R"delim(
          LC_DYLD_INFO.exports out of place:
            Expecting offset: 0x{:x} while it is 0x{:x}
          )delim", offset, dyld_info->export_info().first);
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
  }


  if (const DyldChainedFixups* fixups = binary.dyld_chained_fixups()) {
    if (fixups->data_offset() != 0) {
      if (fixups->data_offset() != offset) {
        if (error != nullptr) {
          *error = fmt::format(R"delim(
          __LINKEDIT does not start with LC_DYLD_CHAINED_FIXUPS:
            Expecting offset: 0x{:x} while it is 0x{:x}
          )delim", offset, fixups->data_offset());
        }
        return false;
      }
      offset += fixups->data_size();
    }
  }

  if (const DyldExportsTrie* exports = binary.dyld_exports_trie()) {
    if (exports->data_offset() != 0) {
      if (exports->data_offset() != offset) {
        if (error != nullptr) {
          *error = fmt::format(R"delim(
          LC_DYLD_EXPORTS_TRIE out of place in __LINKEDIT:
            Expecting offset: 0x{:x} while it is 0x{:x}
          )delim", offset, exports->data_offset());
        }
        return false;
      }
    }
    offset += exports->data_size();
  }

  const DynamicSymbolCommand* dyst = binary.dynamic_symbol_command();
  if (dyst == nullptr) {
    if (error != nullptr) {
      *error = "LC_DYSYMTAB not found";
    }
    return false;
  }

  if (dyst->nb_local_relocations() != 0) {
    if (dyst->local_relocation_offset() != offset) {
      if (error != nullptr) {
          *error = fmt::format(R"delim(
          LC_DYSYMTAB local relocations out of place:
            Expecting offset: 0x{:x} while it is 0x{:x}
          )delim", offset, dyst->local_relocation_offset());
      }
      return false;
    }
    offset += dyst->nb_local_relocations() * sizeof(details::relocation_info);
  }

  // Check consistency of Segment Split Info command
  if (const SegmentSplitInfo* spi = binary.segment_split_info()) {
    if (spi->data_offset() != 0 && spi->data_offset() != offset) {
      if (error != nullptr) {
        *error = fmt::format(R"delim(
        LC_SEGMENT_SPLIT_INFO out of place:
          Expecting offset: 0x{:x} while it is 0x{:x}
        )delim", offset, spi->data_offset());
      }
      return false;
    }
    offset += spi->data_size();
  }

  // Check consistency of Function starts
  if (const FunctionStarts* fs = binary.function_starts()) {
    if (fs->data_offset() != 0 && fs->data_offset() != offset) {
      if (error != nullptr) {
        *error = fmt::format(R"delim(
        LC_FUNCTION_STARTS out of place:
          Expecting offset: 0x{:x} while it is 0x{:x}
        )delim", offset, fs->data_offset());
      }
      return false;
    }
    offset += fs->data_size();
  }

  // Check consistency of Data in Code
  if (const DataInCode* dic = binary.data_in_code()) {
    if (dic->data_offset() != 0 && dic->data_offset() != offset) {
      if (error != nullptr) {
        *error = fmt::format(R"delim(
        LC_DATA_IN_CODE out of place:
          Expecting offset: 0x{:x} while it is 0x{:x}
        )delim", offset, dic->data_offset());
      }
      return false;
    }
    offset += dic->data_size();
  }

  if (const CodeSignatureDir* cs = binary.code_signature_dir()) {
    if (cs->data_offset() != 0 && cs->data_offset() != offset) {
      if (error != nullptr) {
        *error = fmt::format(R"delim(
        LC_DYLIB_CODE_SIGN_DRS out of place:
          Expecting offset: 0x{:x} while it is 0x{:x}
        )delim", offset, cs->data_offset());
      }
      return false;
    }
    offset += cs->data_size();
  }

  if (const LinkerOptHint* opt = binary.linker_opt_hint()) {
    if (opt->data_offset() != 0 && opt->data_offset() != offset) {
      if (error != nullptr) {
        *error = fmt::format(R"delim(
        LC_LINKER_OPTIMIZATION_HINT out of place:
          Expecting offset: 0x{:x} while it is 0x{:x}
        )delim", offset, opt->data_offset());
      }
      return false;
    }
    offset += opt->data_size();
  }

  const SymbolCommand* st = binary.symbol_command();
  if (st == nullptr) {
    if (error != nullptr) {
      *error = "LC_SYMTAB not found!";
    }
    return false;
  }

  if (st->numberof_symbols() != 0) {
    // Check offset
    if (st->symbol_offset() != offset) {
      if (error != nullptr) {
        *error = fmt::format(R"delim(
        LC_SYMTAB.nlist out of place:
          Expecting offset: 0x{:x} while it is 0x{:x}
        )delim", offset, st->symbol_offset());
      }
      return false;
    }
    offset += st->numberof_symbols() * (is64 ? sizeof(details::nlist_64) : sizeof(details::nlist_32));
  }

  size_t isym = 0;

  if (dyst->nb_local_symbols() != 0) {
    if (isym != dyst->idx_local_symbol()) {
      if (error != nullptr) {
        *error = fmt::format(R"delim(
        LC_DYSYMTAB.nlocalsym out of place:
          Expecting index: {} while it is {}
        )delim", isym, dyst->idx_local_symbol());
      }
      return false;
    }
    isym += dyst->nb_local_symbols();
  }


  if (dyst->nb_external_define_symbols() != 0) {
    if (isym != dyst->idx_external_define_symbol()) {
      if (error != nullptr) {
        *error = fmt::format(R"delim(
        LC_DYSYMTAB.iextdefsym out of place:
          Expecting index: {} while it is {}
        )delim", isym, dyst->idx_external_define_symbol());
      }
      return false;
    }
    isym += dyst->nb_external_define_symbols();
  }

  if (dyst->nb_undefined_symbols() != 0) {
    if (isym != dyst->idx_undefined_symbol()) {
      if (error != nullptr) {
        *error = fmt::format(R"delim(
        LC_DYSYMTAB.nundefsym out of place:
          Expecting index: {} while it is {}
        )delim", isym, dyst->idx_undefined_symbol());
      }
      return false;
    }
    isym += dyst->nb_undefined_symbols();
  }


  if (const TwoLevelHints* two = binary.two_level_hints()) {
    if (two->offset() != 0 && two->offset() != offset) {
      if (error != nullptr) {
        *error = fmt::format(R"delim(
        LC_TWOLEVEL_HINTS out of place:
          Expecting offset: 0x{:x} while it is 0x{:x}
        )delim", offset, two->offset());
      }
      return false;
    }
    offset += two->hints().size() * sizeof(details::twolevel_hint);
  }


  if (dyst->nb_external_relocations() != 0) {
    if (dyst->external_relocation_offset() != offset) {
      if (error != nullptr) {
        *error = fmt::format(R"delim(
        LC_DYSYMTAB.extrel out of place:
          Expecting offset: 0x{:x} while it is 0x{:x}
        )delim", offset, dyst->external_relocation_offset());
      }
      return false;
    }

    offset += dyst->nb_external_relocations() * sizeof(details::relocation_info);
  }


  if (dyst->nb_indirect_symbols() != 0) {
    if (dyst->indirect_symbol_offset() != offset) {
      if (error != nullptr) {
        *error = fmt::format(R"delim(
        LC_DYSYMTAB.nindirect out of place:
          Expecting offset: 0x{:x} while it is 0x{:x}
        )delim", offset, dyst->indirect_symbol_offset());
      }
      return false;
    }

    offset += dyst->nb_indirect_symbols() * sizeof(uint32_t);
  }

  uint64_t rounded_offset = offset;
  uint64_t input_indirectsym_pad = 0;
  if (is64 && (dyst->nb_indirect_symbols() % 2) != 0) {
    rounded_offset = rnd(offset, 8);
  }

  if (dyst->toc_offset() != 0) {
    if (dyst->toc_offset() != offset && dyst->toc_offset() != rounded_offset) {
      if (error != nullptr) {
        *error = fmt::format(R"delim(
        LC_DYSYMTAB.toc out of place:
          Expecting offsets: 0x{:x} or 0x{:x} while it is 0x{:x}
        )delim", offset, rounded_offset, dyst->toc_offset());
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
        *error = fmt::format(R"delim(
        LC_DYSYMTAB.modtab out of place:
          Expecting offsets: 0x{:x} or 0x{:x} while it is 0x{:x}
        )delim", offset, rounded_offset, dyst->module_table_offset());
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
        *error = fmt::format(R"delim(
        LC_DYSYMTAB.extrefsym out of place:
          Expecting offsets: 0x{:x} or 0x{:x} while it is 0x{:x}
        )delim", offset, rounded_offset, dyst->external_reference_symbol_offset());
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
        *error = fmt::format(R"delim(
        LC_SYMTAB.strings out of place:
          Expecting offsets: 0x{:x} or 0x{:x} while it is 0x{:x}
        )delim", offset, rounded_offset, st->strings_offset());
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

  if (const CodeSignature* cs = binary.code_signature()) {
    rounded_offset = align(rounded_offset, 16);
    if (cs->data_offset() != rounded_offset) {
      if (error != nullptr) {
        *error = fmt::format(R"delim(
        LC_CODE_SIGNATURE out of place:
          Expecting offsets: 0x{:x} while it is 0x{:x}
        )delim", offset, cs->data_offset());
      }
      return false;
    }
    rounded_offset += cs->data_size();
    offset = rounded_offset;
  }

  LIEF_DEBUG("input_indirectsym_pad: {:x}", input_indirectsym_pad);
  const uint64_t object_size = linkedit->file_offset() + linkedit->file_size();
  if (offset != object_size && rounded_offset != object_size) {
    if (error != nullptr) {
      *error = fmt::format(R"delim(
      __LINKEDIT.end (0x{:x}) does not match 0x{:x} nor 0x{:x}
      )delim", object_size, offset, rounded_offset);
    }
    return false;
  }
  return true;
}

}
}

