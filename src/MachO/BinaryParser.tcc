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

#include <memory>

#include "logging.hpp"

#include "LIEF/BinaryStream/VectorStream.hpp"
#include "LIEF/BinaryStream/SpanStream.hpp"

#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/BinaryParser.hpp"
#include "LIEF/MachO/ChainedBindingInfo.hpp"
#include "LIEF/MachO/CodeSignature.hpp"
#include "LIEF/MachO/CodeSignatureDir.hpp"
#include "LIEF/MachO/DataInCode.hpp"
#include "LIEF/MachO/DyldBindingInfo.hpp"
#include "LIEF/MachO/DyldChainedFixups.hpp"
#include "LIEF/MachO/DyldEnvironment.hpp"
#include "LIEF/MachO/DyldExportsTrie.hpp"
#include "LIEF/MachO/DyldInfo.hpp"
#include "LIEF/MachO/DylibCommand.hpp"
#include "LIEF/MachO/DylinkerCommand.hpp"
#include "LIEF/MachO/DynamicSymbolCommand.hpp"
#include "LIEF/MachO/EncryptionInfo.hpp"
#include "LIEF/MachO/EnumToString.hpp"
#include "LIEF/MachO/FilesetCommand.hpp"
#include "LIEF/MachO/FunctionStarts.hpp"
#include "LIEF/MachO/LinkEdit.hpp"
#include "LIEF/MachO/LinkerOptHint.hpp"
#include "LIEF/MachO/MainCommand.hpp"
#include "LIEF/MachO/RPathCommand.hpp"
#include "LIEF/MachO/Relocation.hpp"
#include "LIEF/MachO/RelocationDyld.hpp"
#include "LIEF/MachO/RelocationFixup.hpp"
#include "LIEF/MachO/RelocationObject.hpp"
#include "LIEF/MachO/Section.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"
#include "LIEF/MachO/SegmentSplitInfo.hpp"
#include "LIEF/MachO/SourceVersion.hpp"
#include "LIEF/MachO/SubFramework.hpp"
#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/SymbolCommand.hpp"
#include "LIEF/MachO/ThreadCommand.hpp"
#include "LIEF/MachO/TwoLevelHints.hpp"
#include "LIEF/MachO/UUIDCommand.hpp"
#include "LIEF/MachO/VersionMin.hpp"

#include "MachO/Structures.hpp"
#include "MachO/ChainedFixup.hpp"

#include "Object.tcc"


namespace LIEF {
namespace MachO {

static constexpr uint8_t BYTE_BITS = std::numeric_limits<uint8_t>::digits;
static_assert(BYTE_BITS == 8, "The number of bits in a byte is not 8");

namespace {
struct ThreadedBindData {
  std::string symbol_name;
  int64_t addend          = 0;
  int64_t library_ordinal = 0;
  uint8_t symbol_flags    = 0;
  uint8_t type            = 0;
};
}



template<class MACHO_T>
ok_error_t BinaryParser::parse() {
  parse_header<MACHO_T>();
  if (binary_->header().nb_cmds() > 0) {
    parse_load_commands<MACHO_T>();
  }


  /*
   * We must before this post-processing BEFORE parsing
   * the exports trie as it could create new symbols and break the DynamicSymbolCommand's indexes
   */
  if (DynamicSymbolCommand* dynsym = binary_->dynamic_symbol_command()) {
    post_process<MACHO_T>(*dynsym);
  }

  for (Section& section : binary_->sections()) {
    parse_relocations<MACHO_T>(section);
  }

  if (binary_->has_dyld_info()) {

    if (config_.parse_dyld_exports) {
      parse_dyldinfo_export();
    }

    if (config_.parse_dyld_bindings) {
      parse_dyldinfo_binds<MACHO_T>();
    }

    if (config_.parse_dyld_rebases) {
      parse_dyldinfo_rebases<MACHO_T>();
    }
  }

  if (config_.parse_dyld_exports && binary_->has_dyld_exports_trie()) {
    parse_dyld_exports();
  }

  if (SegmentCommand* seg = binary_->get_segment("__LINKEDIT")) {
    LinkEdit& linkedit = *static_cast<LinkEdit*>(seg);

    // Backtrack the objects in the segment to keep span consistent
    if (DyldInfo* dyld = binary_->dyld_info()) {
      linkedit.dyld_ = dyld;
    }

    if (DyldChainedFixups* fixups = binary_->dyld_chained_fixups()) {
      linkedit.chained_fixups_ = fixups;
    }
  }


  if (DyldChainedFixups* fixups = binary_->dyld_chained_fixups()) {
    LIEF_DEBUG("[+] Parsing LC_DYLD_CHAINED_FIXUPS payload");
    SpanStream stream = fixups->content_;
    chained_fixups_ = fixups;
    auto is_ok = parse_chained_payload<MACHO_T>(stream);
    if (!is_ok) {
      LIEF_WARN("Error while parsing the payload of LC_DYLD_CHAINED_FIXUPS");
    }
  }

  /*
   * Create the slices for the LinkEdit commands
   */
  if (SymbolCommand* symtab = binary_->symbol_command()) {
    post_process<MACHO_T>(*symtab);
  }
  if (FunctionStarts* fstart = binary_->function_starts()) {
    post_process<MACHO_T>(*fstart);
  }
  if (DataInCode* data_code = binary_->data_in_code()) {
    post_process<MACHO_T>(*data_code);
  }
  if (SegmentSplitInfo* split = binary_->segment_split_info()) {
    post_process<MACHO_T>(*split);
  }
  if (TwoLevelHints* two = binary_->two_level_hints()) {
    post_process<MACHO_T>(*two);
  }
  if (CodeSignature* sig = binary_->code_signature()) {
    post_process<MACHO_T>(*sig);
  }
  if (CodeSignatureDir* sig = binary_->code_signature_dir()) {
    post_process<MACHO_T>(*sig);
  }
  if (LinkerOptHint* opt = binary_->linker_opt_hint()) {
    post_process<MACHO_T>(*opt);
  }
  return ok();
}

template<class MACHO_T>
ok_error_t BinaryParser::parse_header() {
  using header_t = typename MACHO_T::header;
  auto hdr = stream_->read<header_t>();
  if (!hdr) {
    LIEF_ERR("Can't read the Mach-O header");
    return make_error_code(lief_errors::parsing_error);
  }
  binary_->header_ = std::move(*hdr);
  LIEF_DEBUG("Arch: {}", to_string(binary_->header_.cpu_type()));
  return ok();
}


template<class MACHO_T>
ok_error_t BinaryParser::parse_load_commands() {
  using segment_command_t = typename MACHO_T::segment_command;
  using section_t         = typename MACHO_T::section;

  LIEF_DEBUG("[+] Building Load commands");

  const Header& header = binary_->header();
  uint64_t loadcommands_offset = stream_->pos();

  if ((loadcommands_offset + header.sizeof_cmds()) > stream_->size()) {
    LIEF_ERR("Load commands are corrupted");
    return make_error_code(lief_errors::corrupted);
  }

  size_t nbcmds = header.nb_cmds();

  if (header.nb_cmds() > BinaryParser::MAX_COMMANDS) {
    nbcmds = BinaryParser::MAX_COMMANDS;
    LIEF_WARN("Only the first #{:d} will be parsed", nbcmds);
  }

  uint32_t low_fileoff = -1U;
  for (size_t i = 0; i < nbcmds; ++i) {
    const auto command = stream_->peek<details::load_command>(loadcommands_offset);
    if (!command) {
      break;
    }

    std::unique_ptr<LoadCommand> load_command;
    switch (static_cast<LOAD_COMMAND_TYPES>(command->cmd)) {

      // ===============
      // Segment command
      // ===============
      case LOAD_COMMAND_TYPES::LC_SEGMENT_64:
      case LOAD_COMMAND_TYPES::LC_SEGMENT:
        {
          /*
           * DO NOT FORGET TO UPDATE SegmentCommand::classof
           */
          uint64_t local_offset = loadcommands_offset;
          const auto segment_cmd = stream_->peek<segment_command_t>(loadcommands_offset);
          if (!segment_cmd) {
            LIEF_ERR("Can't parse segment command #{}", i);
            break;
          }

          if (std::string(segment_cmd->segname, 10) == "__LINKEDIT") {
            load_command = std::make_unique<LinkEdit>(*segment_cmd);
          } else {
            load_command = std::make_unique<SegmentCommand>(*segment_cmd);
          }

          local_offset += sizeof(segment_command_t);

          auto* segment = load_command->as<SegmentCommand>();
          segment->index_ = binary_->segments_.size();
          binary_->offset_seg_[segment->file_offset()] = segment;
          binary_->segments_.push_back(segment);

          if (segment->file_size() > 0) {
            if (!stream_->peek_data(segment->data_, segment->file_offset(), segment->file_size())) {
              LIEF_ERR("Segment {}: content corrupted!", segment->name());
            }
          }

          // --------
          // Sections
          // --------
          for (size_t j = 0; j < segment->numberof_sections(); ++j) {
            const auto section_header = stream_->peek<section_t>(local_offset);
            if (!section_header) {
              LIEF_ERR("Can't parse section in {}#{}",
                       load_command->as<SegmentCommand>()->name(), i);
              break;
            }
            auto section = std::make_unique<Section>(*section_header);
            binary_->sections_.push_back(section.get());
            if (section->size_ > 0 &&
                section->type() != MACHO_SECTION_TYPES::S_ZEROFILL &&
                section->type() != MACHO_SECTION_TYPES::S_THREAD_LOCAL_ZEROFILL &&
                section->offset_ < low_fileoff)
            {
              low_fileoff = section->offset_;
            }
            section->segment_ = segment;
            segment->sections_.push_back(std::move(section));
            local_offset += sizeof(section_t);
          }
          if (segment->numberof_sections() == 0 &&
              segment->file_offset() != 0 &&
              segment->file_size() != 0 &&
              segment->file_offset() < low_fileoff)
          {
            low_fileoff = segment->file_offset();
          }
          break;
        }


      // =============
      // DyLib Command
      // =============
      case LOAD_COMMAND_TYPES::LC_LOAD_WEAK_DYLIB:
      case LOAD_COMMAND_TYPES::LC_ID_DYLIB:
      case LOAD_COMMAND_TYPES::LC_LOAD_DYLIB:
      case LOAD_COMMAND_TYPES::LC_REEXPORT_DYLIB:
      case LOAD_COMMAND_TYPES::LC_LOAD_UPWARD_DYLIB:
      case LOAD_COMMAND_TYPES::LC_LAZY_LOAD_DYLIB:
        {
          /*
           * DO NOT FORGET TO UPDATE DylibCommand::classof
           */
          const auto cmd = stream_->peek<details::dylib_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't read dylib_command");
            break;
          }

          load_command = std::make_unique<DylibCommand>(*cmd);
          const uint32_t str_name_offset = cmd->dylib.name;
          auto name = stream_->peek_string_at(loadcommands_offset + str_name_offset);
          if (!name) {
            LIEF_ERR("Can't read Dylib string value");
            break;
          }

          auto* lib = load_command->as<DylibCommand>();
          lib->name(*name);
          binary_->libraries_.push_back(lib);
          if (static_cast<LOAD_COMMAND_TYPES>(command->cmd) != LOAD_COMMAND_TYPES::LC_ID_DYLIB) {
            binding_libs_.push_back(lib);
          }
          break;
        }

      // =============
      // RPath Command
      // =============
      case LOAD_COMMAND_TYPES::LC_RPATH:
        {
          /*
           * DO NOT FORGET TO UPDATE RPathCommand::classof
           */
          const auto cmd = stream_->peek<details::rpath_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't read rpath_command");
            break;
          }

          load_command = std::make_unique<RPathCommand>(*cmd);
          const uint32_t str_path_offset = cmd->path;
          auto path = stream_->peek_string_at(loadcommands_offset + str_path_offset);
          if (!path) {
            LIEF_ERR("Can't read rpath_command.path");
            break;
          }

          load_command->as<RPathCommand>()->path(*path);
          break;
        }

      // ====
      // UUID
      // ====
      case LOAD_COMMAND_TYPES::LC_UUID:
        {
          /*
           * DO NOT FORGET TO UPDATE UUIDCommand::classof
           */
          LIEF_DEBUG("[+] Building UUID");
          const auto cmd = stream_->peek<details::uuid_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't read uuid_command");
            break;
          }
          load_command = std::make_unique<UUIDCommand>(*cmd);
          break;
        }

      // ==============
      // Dynamic Linker
      // ==============
      case LOAD_COMMAND_TYPES::LC_LOAD_DYLINKER:
      case LOAD_COMMAND_TYPES::LC_ID_DYLINKER:
        {
          /*
           * DO NOT FORGET TO UPDATE DylinkerCommand::classof
           */
          const auto cmd = stream_->peek<details::dylinker_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't read dylinker_command");
            break;
          }

          load_command = std::make_unique<DylinkerCommand>(*cmd);

          const uint32_t linker_name_offset = cmd->name;
          auto name = stream_->peek_string_at(loadcommands_offset + linker_name_offset);
          if (!name) {
            LIEF_ERR("Can't read dylinker_command.name");
            break;
          }
          load_command->as<DylinkerCommand>()->name(*name);
          break;
        }

      // ======
      // Thread
      // ======
      case LOAD_COMMAND_TYPES::LC_THREAD:
      case LOAD_COMMAND_TYPES::LC_UNIXTHREAD:
        {
          /*
           * DO NOT FORGET TO UPDATE ThreadCommand::classof
           */
          LIEF_DEBUG("[+] Parsing LC_THREAD");

          const auto cmd = stream_->peek<details::thread_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't read thread_command");
            break;
          }
          load_command = std::make_unique<ThreadCommand>(*cmd);

          auto* thread = load_command->as<ThreadCommand>();
          thread->architecture_ = binary_->header().cpu_type();
          LIEF_DEBUG("FLAVOR: {} | COUNT: {}", cmd->flavor, cmd->count);
          const uint64_t state_offset = loadcommands_offset + sizeof(details::thread_command);
          switch (binary_->header().cpu_type()) {
            case CPU_TYPES::CPU_TYPE_X86:
              {
                if (!stream_->peek_data(thread->state_, state_offset, sizeof(details::x86_thread_state_t))) {
                  LIEF_ERR("Can't read the state data");
                }
                break;
              }

            case CPU_TYPES::CPU_TYPE_X86_64:
              {
                if (!stream_->peek_data(thread->state_, state_offset, sizeof(details::x86_thread_state64_t))) {
                  LIEF_ERR("Can't read the state data");
                }
                break;
              }

            case CPU_TYPES::CPU_TYPE_ARM:
              {
                if (!stream_->peek_data(thread->state_, state_offset, sizeof(details::arm_thread_state_t))) {
                  LIEF_ERR("Can't read the state data");
                }
                break;
              }

            case CPU_TYPES::CPU_TYPE_ARM64:
              {
                if (!stream_->peek_data(thread->state_, state_offset, sizeof(details::arm_thread_state64_t))) {
                  LIEF_ERR("Can't read the state data");
                }
                break;
              }
            default:
              {
                LIEF_ERR("Unknown architecture");
              }
          }
          break;
        }

      // ===============
      // Routine command
      // ===============
      //case LOAD_COMMAND_TYPES::LC_ROUTINES:
      //case LOAD_COMMAND_TYPES::LC_ROUTINES_64:
      //  {
      //    LIEF_DEBUG("[+] Parsing LC_ROUTINE");
      //    load_command = std::unique_ptr<LoadCommand>{new LoadCommand{command}};
      //    break;
      //  }

      // =============
      // Symbols table
      // =============
      case LOAD_COMMAND_TYPES::LC_SYMTAB:
        {
          /*
           * DO NOT FORGET TO UPDATE SymbolCommand::classof
           */
          using nlist_t = typename MACHO_T::nlist;
          LIEF_DEBUG("[+] Parsing symbols");

          const auto cmd = stream_->peek<details::symtab_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't read symtab_command");
            break;
          }

          load_command = std::make_unique<SymbolCommand>(*cmd);
          stream_->setpos(cmd->symoff);
          for (size_t j = 0; j < cmd->nsyms; ++j) {
            auto nlist = stream_->read<nlist_t>();
            if (!nlist) {
              LIEF_ERR("Can't read nlist #{}", i);
              break;
            }
            auto symbol = std::make_unique<Symbol>(*nlist);
            const uint32_t str_idx = nlist->n_strx;
            const auto end_strings = cmd->stroff + cmd->strsize;
            if (cmd->stroff + str_idx < end_strings) {
              if (str_idx > 0) {
                if (auto name = stream_->peek_string_at(cmd->stroff + str_idx)) {
                  symbol->name(*name);
                  memoized_symbols_[*name] = symbol.get();
                } else {
                  LIEF_WARN("Can't read symbol's name for nlist #{}", i);
                }
              }
            } else {
              LIEF_ERR("nlist[{}].str_idx seems corrupted (0x{:08x})", j, str_idx);
            }
            memoized_symbols_by_address_[symbol->value()] = symbol.get();
            binary_->symbols_.push_back(std::move(symbol));
          }
          break;
        }

      // ===============
      // Dynamic Symbols
      // ===============
      case LOAD_COMMAND_TYPES::LC_DYSYMTAB:
        {
          /*
           * DO NOT FORGET TO UPDATE DynamicSymbolCommand::classof
           */
          LIEF_DEBUG("[+] Parsing dynamic symbols");
          const auto cmd = stream_->peek<details::dysymtab_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't parse dysymtab_command");
            break;
          }
          load_command = std::make_unique<DynamicSymbolCommand>(*cmd);
          break;
        }

      // ===============
      // Dyd Info
      // ===============
      case LOAD_COMMAND_TYPES::LC_DYLD_INFO:
      case LOAD_COMMAND_TYPES::LC_DYLD_INFO_ONLY:
        {
          /*
           * DO NOT FORGET TO UPDATE DyldInfo::classof
           */
          LIEF_DEBUG("[+] Parsing dyld information");
          const auto cmd = stream_->peek<details::dyld_info_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't parse dyld_info_command");
            break;
          }
          load_command = std::make_unique<DyldInfo>(*cmd);
          load_command->as<DyldInfo>()->binary_ = binary_.get();
          break;
        }

      // ===============
      // Source Version
      // ===============
      case LOAD_COMMAND_TYPES::LC_SOURCE_VERSION:
        {
          /*
           * DO NOT FORGET TO UPDATE SourceVersion::classof
           */
          LIEF_DEBUG("[+] Parsing LC_SOURCE_VERSION");

          const auto cmd = stream_->peek<details::source_version_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't parse source_version_command");
            break;
          }
          load_command = std::make_unique<SourceVersion>(*cmd);
          LIEF_DEBUG("Version: 0x{:x}", cmd->version);
          break;
        }

      case LOAD_COMMAND_TYPES::LC_VERSION_MIN_MACOSX:
      case LOAD_COMMAND_TYPES::LC_VERSION_MIN_IPHONEOS:
        {
          /*
           * DO NOT FORGET TO UPDATE VersionMin::classof
           */
          LIEF_DEBUG("[+] Parsing {}", to_string(static_cast<LOAD_COMMAND_TYPES>(command->cmd)));

          const auto cmd = stream_->peek<details::version_min_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't parse version_min_command");
            break;
          }
          LIEF_DEBUG("Version: 0x{:x} | SDK: 0x{:x}", cmd->version, cmd->sdk);

          load_command = std::make_unique<VersionMin>(*cmd);
          break;
        }


      case LOAD_COMMAND_TYPES::LC_BUILD_VERSION:
        {
          /*
           * DO NOT FORGET TO UPDATE BuildVersion::classof
           */
          LIEF_DEBUG("[+] Parsing {}", to_string(static_cast<LOAD_COMMAND_TYPES>(command->cmd)));

          const auto cmd = stream_->peek<details::build_version_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't parse build_version_command");
            break;
          }

          load_command = std::make_unique<BuildVersion>(*cmd);
          auto* build_version = load_command->as<BuildVersion>();
          for (size_t i = 0; i < cmd->ntools; ++i) {
            const uint64_t cmd_offset = loadcommands_offset + sizeof(details::build_version_command) +
                                        i * sizeof(details::build_tool_version);

            auto tool_struct = stream_->peek<details::build_tool_version>(cmd_offset);
            if (!tool_struct) {
              break;
            }
            build_version->tools_.emplace_back(*tool_struct);
          }
          break;
        }

      // =================
      // Code Signature
      // =================
      case LOAD_COMMAND_TYPES::LC_DYLIB_CODE_SIGN_DRS:
        {
          /*
           * DO NOT FORGET TO UPDATE CodeSignatureDir::classof
           */
          if (auto cmd = stream_->peek<details::linkedit_data_command>(loadcommands_offset)) {
            load_command = std::make_unique<CodeSignatureDir>(*cmd);
          } else {
            LIEF_ERR("Can't parse linkedit_data_command for LC_DYLIB_CODE_SIGN_DRS");
          }
          break;
        }

      case LOAD_COMMAND_TYPES::LC_CODE_SIGNATURE:
        {
          /*
           * DO NOT FORGET TO UPDATE CodeSignature::classof
           */
          if (auto cmd = stream_->peek<details::linkedit_data_command>(loadcommands_offset)) {
            load_command = std::make_unique<CodeSignature>(*cmd);
          } else {
            LIEF_ERR("Can't parse linkedit_data_command for LC_CODE_SIGNATURE");
          }
          break;
        }

      // ==============
      // Data in Code
      // ==============
      case LOAD_COMMAND_TYPES::LC_DATA_IN_CODE:
        {
          /*
           * DO NOT FORGET TO UPDATE DataInCode::classof
           */
          const auto cmd = stream_->peek<details::linkedit_data_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't parse linkedit_data_command for LC_DATA_IN_CODE");
            break;
          }
          load_command = std::make_unique<DataInCode>(*cmd);
          auto* datacode = load_command->as<DataInCode>();

          const size_t nb_entries = datacode->data_size() / sizeof(details::data_in_code_entry);
          stream_->setpos(datacode->data_offset());

          for (size_t i = 0; i < nb_entries; ++i) {
            if (auto entry = stream_->read<details::data_in_code_entry>()) {
              datacode->add(*entry);
            } else {
              LIEF_ERR("Can't read data in code entry #{}", i);
              break;
            }
          }
          break;
        }


      // =======
      // LC_MAIN
      // =======
      case LOAD_COMMAND_TYPES::LC_MAIN:
        {
          /*
           * DO NOT FORGET TO UPDATE MainCommand::classof
           */
          LIEF_DEBUG("[+] Parsing LC_MAIN");
          const auto cmd = stream_->peek<details::entry_point_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't parse entry_point_command");
            break;
          }
          load_command = std::make_unique<MainCommand>(*cmd);
          break;
        }

      // ==================
      // LC_FUNCTION_STARTS
      // ==================
      case LOAD_COMMAND_TYPES::LC_FUNCTION_STARTS:
        {
          /*
           * DO NOT FORGET TO UPDATE FunctionStarts::classof
           */
          LIEF_DEBUG("[+] Parsing LC_FUNCTION_STARTS");
          const auto cmd = stream_->peek<details::linkedit_data_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't parse linkedit_data_command for LC_FUNCTION_STARTS");
            break;
          }
          load_command = std::make_unique<FunctionStarts>(*cmd);

          uint64_t value = 0;
          auto* fstart = load_command->as<FunctionStarts>();
          stream_->setpos(cmd->dataoff);

          do {
            auto val = stream_->read_uleb128();
            if (!val || *val == 0) {
              break;
            }
            value += *val;

            //LIEF_DEBUG("Value: 0x{:x}", value);
            fstart->add_function(value);
          } while(stream_->pos() < (cmd->dataoff + cmd->datasize));

          break;
        }

      case LOAD_COMMAND_TYPES::LC_SEGMENT_SPLIT_INFO:
        {
          /*
           * DO NOT FORGET TO UPDATE SegmentSplitInfo::classof
           */
          //static constexpr uint8_t DYLD_CACHE_ADJ_V2_FORMAT = 0x7F;
          LIEF_DEBUG("[+] Parsing LC_SEGMENT_SPLIT_INFO");
          const auto cmd = stream_->peek<details::linkedit_data_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't parse linkedit_data_command for LC_SEGMENT_SPLIT_INFO");
            break;
          }
          load_command = std::make_unique<SegmentSplitInfo>(*cmd);
          //const uint32_t start = cmd->dataoff;
          //const uint32_t size  = cmd->datasize;

          //load_command = std::unique_ptr<LoadCommand>{new LoadCommand{&command}};

          //const size_t saved_pos = stream_->pos();
          //stream_->setpos(start);

          //// 1. Type
          //uint8_t kind = stream_->peek<uint8_t>();
          //if (kind == DYLD_CACHE_ADJ_V2_FORMAT) {
          //  std::cout  << "V2 Format" << std::endl;
          //} else {
          //  std::cout  << "V1 Format" << std::endl;
          //  while (stream_->pos() < (start + size)) {
          //    uint8_t kind = stream_->read<uint8_t>();
          //    uint64_t cache_offset = 0;
          //    while (uint64_t delta = stream_->read_uleb128()) {
          //      cache_offset += delta;
          //    }
          //  }
          //}
          //stream_->setpos(saved_pos);
          break;

        }

      case LOAD_COMMAND_TYPES::LC_SUB_FRAMEWORK:
        {
          /*
           * DO NOT FORGET TO UPDATE SubFramework::classof
           */
          const auto cmd = stream_->peek<details::sub_framework_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't parse sub_framework_command");
            break;
          }
          auto u = stream_->peek_string_at(loadcommands_offset + cmd->umbrella);
          if (!u) {
            LIEF_ERR("Can't read umbrella string");
            break;
          }
          auto sf = std::make_unique<SubFramework>(*cmd);
          sf->umbrella(*u);
          load_command = std::move(sf);
          break;
        }


      case LOAD_COMMAND_TYPES::LC_DYLD_ENVIRONMENT:
        {
          /*
           * DO NOT FORGET TO UPDATE DyldEnvironment::classof
           */
          const auto cmd = stream_->peek<details::dylinker_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't parse dylinker_command");
            break;
          }

          auto value = stream_->peek_string_at(loadcommands_offset + cmd->name);
          if (!value) {
            LIEF_ERR("Can't read dylinker_command.name");
            break;
          }
          auto env = std::make_unique<DyldEnvironment>(*cmd);
          env->value(*value);
          load_command = std::move(env);
          break;
        }


      // ================
      // Encryption Info
      // ================
      case LOAD_COMMAND_TYPES::LC_ENCRYPTION_INFO:
      case LOAD_COMMAND_TYPES::LC_ENCRYPTION_INFO_64:
        {
          /*
           * DO NOT FORGET TO UPDATE EncryptionInfo::classof
           */
          LIEF_DEBUG("[+] Parsing {}", to_string(static_cast<LOAD_COMMAND_TYPES>(command->cmd)));
          const auto cmd = stream_->peek<details::encryption_info_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't parse encryption_info_command");
            break;
          }
          load_command = std::make_unique<EncryptionInfo>(*cmd);
          break;
        }

      // ==============
      // File Set Entry
      // ==============
      case LOAD_COMMAND_TYPES::LC_FILESET_ENTRY:
        {
          /*
           * DO NOT FORGET TO UPDATE FilesetCommand::classof
           */
          LIEF_DEBUG("[+] Parsing {}", to_string(static_cast<LOAD_COMMAND_TYPES>(command->cmd)));

          const auto cmd = stream_->peek<details::fileset_entry_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't parse fileset_entry_command");
            break;
          }
          load_command = std::make_unique<FilesetCommand>(*cmd);
          const uint32_t entry_offset = cmd->entry_id;
          auto entry_name = stream_->peek_string_at(loadcommands_offset + entry_offset);

          if (!entry_name) {
            LIEF_ERR("Can't read fileset_entry_command.entry_id");
            break;
          }

          auto* fset = load_command->as<FilesetCommand>();
          fset->name(*entry_name);

          LIEF_DEBUG("Parsing fileset '{}' @ {:x} (size: {:x})",
                     fset->name(), cmd->fileoff, cmd->cmdsize);
          auto res_type = stream_->peek<uint32_t>(cmd->fileoff);
          if (!res_type) {
            LIEF_ERR("Can't access fileset_entry_command.fileoff");
            break;
          }
          auto type = static_cast<MACHO_TYPES>(*res_type);

          // Fat binary
          if (type == MACHO_TYPES::FAT_MAGIC || type == MACHO_TYPES::FAT_CIGAM) {
            LIEF_ERR("Mach-O is corrupted with a FAT Mach-O inside a fileset ?");
            break;
          }


          /* TODO(romain): This part needs to be refactored
           * we should not have to make this kind construction and move
           * with the BinaryParser constructor
           */
          const size_t current_pos = stream_->pos();
          if (!visited_.insert(cmd->fileoff).second) {
            break;
          }

          stream_->setpos(cmd->fileoff);
          BinaryParser bp;
          bp.binary_  = std::unique_ptr<Binary>(new Binary{});
          bp.stream_  = std::move(stream_);
          bp.config_  = config_;
          bp.visited_ = visited_;

          if (!bp.init_and_parse()) {
            LIEF_WARN("Parsing the Binary fileset raised error.");
          }

          stream_ = std::move(bp.stream_);
          stream_->setpos(current_pos);
          visited_ = std::move(bp.visited_);

          if (bp.binary_ != nullptr) {
            std::unique_ptr<Binary> filset_bin = std::move(bp.binary_);
            filset_bin->name_ = *entry_name;
            binary_->filesets_.push_back(std::move(filset_bin));
          }
          break;
        }
      case LOAD_COMMAND_TYPES::LC_DYLD_CHAINED_FIXUPS:
        {
          LIEF_DEBUG("[->] LC_DYLD_CHAINED_FIXUPS");
          const auto cmd = stream_->peek<details::linkedit_data_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't parse linkedit_data_command for LC_DYLD_CHAINED_FIXUPS");
            break;
          }

          LIEF_DEBUG("[*] dataoff:  0x{:x}", cmd->dataoff);
          LIEF_DEBUG("[*] datasize: 0x{:x}", cmd->datasize);

          load_command = std::make_unique<DyldChainedFixups>(*cmd);
          auto* chained = load_command->as<DyldChainedFixups>();
          SegmentCommand* lnk = binary_->segment_from_offset(chained->data_offset());
          if (lnk == nullptr) {
            LIEF_WARN("Can't find the segment associated with "
                      "the LC_DYLD_CHAINED_FIXUPS payload (offset: 0x{:x})", chained->data_offset());
            break;
          }
          LIEF_DEBUG("LC_DYLD_CHAINED_FIXUPS payload in '{}'", lnk->name());
          span<uint8_t> content = lnk->writable_content();

          if ((chained->data_offset() + chained->data_size()) > (lnk->file_offset() + content.size())) {
            LIEF_WARN("LC_DYLD_CHAINED_FIXUPS payload does not fit in the '{}' segments",
                      lnk->name());
            LIEF_DEBUG("{}.file_size: 0x{:x}", lnk->name(), lnk->file_size());
            break;
          }
          const uint64_t rel_offset = chained->data_offset() - lnk->file_offset();
          chained->content_ = content.subspan(rel_offset, chained->data_size());
          break;
        }

      case LOAD_COMMAND_TYPES::LC_DYLD_EXPORTS_TRIE:
        {
          LIEF_DEBUG("[->] LC_DYLD_EXPORTS_TRIE");
          if (const auto cmd = stream_->peek<details::linkedit_data_command>(loadcommands_offset)) {
            LIEF_DEBUG("[*] dataoff:  0x{:x}", cmd->dataoff);
            LIEF_DEBUG("[*] datasize: 0x{:x}", cmd->datasize);

            load_command = std::make_unique<DyldExportsTrie>(*cmd);
          } else {
            LIEF_ERR("Can't parse linkedit_data_command for LC_DYLD_EXPORTS_TRIE");
          }
          break;
        }

      case LOAD_COMMAND_TYPES::LC_TWOLEVEL_HINTS:
        {
          LIEF_DEBUG("[->] LC_TWOLEVEL_HINTS");
          if (const auto cmd = stream_->peek<details::twolevel_hints_command>(loadcommands_offset)) {
            load_command = std::make_unique<TwoLevelHints>(*cmd);
            auto* two = load_command->as<TwoLevelHints>();
            {
              ScopedStream scoped(*stream_, cmd->offset);
              two->hints_.reserve(std::min<size_t>(0x1000, cmd->nhints));
              for (size_t i = 0; i < cmd->nhints; ++i) {
                if (auto res = stream_->read<details::twolevel_hint>()) {
                  uint32_t raw = 0;
                  memcpy(&raw, &*res, sizeof(raw));
                  two->hints_.push_back(raw);
                } else {
                  LIEF_WARN("Can't read LC_TWOLEVEL_HINTS.hints[{}]", i);
                  break;
                }
              }
            }
          } else {
            LIEF_ERR("Can't parse twolevel_hints_command for LC_TWOLEVEL_HINTS");
          }
          break;
        }


      case LOAD_COMMAND_TYPES::LC_LINKER_OPTIMIZATION_HINT:
        {
          LIEF_DEBUG("[->] LC_LINKER_OPTIMIZATION_HINT");
          if (const auto cmd = stream_->peek<details::linkedit_data_command>(loadcommands_offset)) {
            LIEF_DEBUG("  [*] dataoff:  0x{:x}", cmd->dataoff);
            LIEF_DEBUG("  [*] datasize: 0x{:x}", cmd->datasize);

            load_command = std::make_unique<LinkerOptHint>(*cmd);
          } else {
            LIEF_ERR("Can't parse linkedit_data_command for LC_LINKER_OPTIMIZATION_HINT");
          }
          break;
        }

      default:
        {
          LIEF_WARN("Command '{}' not parsed!", to_string(static_cast<LOAD_COMMAND_TYPES>(command->cmd)));
          load_command = std::make_unique<LoadCommand>(*command);
        }
    }

    if (load_command != nullptr) {
      if (!stream_->peek_data(load_command->original_data_, loadcommands_offset, command->cmdsize)) {
        LIEF_ERR("Can't read the raw data of the load command");
        load_command->size_ = 0;
      }
      load_command->command_offset(loadcommands_offset);
      binary_->commands_.push_back(std::move(load_command));
    }
    loadcommands_offset += command->cmdsize;
  }
  binary_->available_command_space_ = low_fileoff - loadcommands_offset;
  return ok();
}


template<class MACHO_T>
ok_error_t BinaryParser::parse_relocations(Section& section) {
  if (section.numberof_relocations() == 0) {
    LIEF_DEBUG("No relocations in {}", section.name());
    return ok();
  }

  LIEF_DEBUG("Parse '{}' relocations (#{:d})", section.name(), section.numberof_relocations());

  uint64_t current_reloc_offset = section.relocation_offset();
  size_t numberof_relocations = section.numberof_relocations();
  if (section.numberof_relocations() > BinaryParser::MAX_RELOCATIONS) {
    numberof_relocations = BinaryParser::MAX_RELOCATIONS;
    LIEF_WARN("Huge number of relocations (#{:d}). Only the first #{:d} will be parsed",
              section.numberof_relocations(), numberof_relocations);

  }
  if (current_reloc_offset + numberof_relocations * 2 * sizeof(uint32_t) > stream_->size()) {
    LIEF_WARN("Relocations corrupted");
    return make_error_code(lief_errors::corrupted);
  }

  for (size_t i = 0; i < numberof_relocations; ++i) {
    std::unique_ptr<RelocationObject> reloc;
    int32_t address = 0;
    if (auto res = stream_->peek<int32_t>(current_reloc_offset)) {
      address = *res;
    } else {
      LIEF_INFO("Can't read relocation address for #{}@0x{:x}", i, address);
      break;
    }
    bool is_scattered = static_cast<bool>(address & R_SCATTERED);

    if (is_scattered) {
      if (auto res = stream_->peek<details::scattered_relocation_info>(current_reloc_offset)) {
        reloc = std::make_unique<RelocationObject>(*res);
        reloc->section_ = &section;
      } else {
        LIEF_INFO("Can't read scattered_relocation_info for #{}@0x{:x}", i, current_reloc_offset);
        break;
      }
    } else {
      details::relocation_info reloc_info;
      if (auto res = stream_->peek<details::relocation_info>(current_reloc_offset)) {
        reloc_info = *res;
        reloc = std::make_unique<RelocationObject>(*res);
        reloc->section_ = &section;
      } else {
        LIEF_INFO("Can't read relocation_info for #{}@0x{:x}", i, current_reloc_offset);
        break;
      }

      const auto symbols = binary_->symbols();
      if (reloc_info.r_extern == 1 && reloc_info.r_symbolnum != R_ABS) {
        if (reloc_info.r_symbolnum < symbols.size()) {
          Symbol& symbol = symbols[reloc_info.r_symbolnum];
          reloc->symbol_ = &symbol;

          LIEF_DEBUG("Symbol: {}", symbol.name());
        } else {
          LIEF_WARN("Relocation #{:d} of {} symbol index is out-of-bound", i, section.name());
        }
      }
      const auto sections = binary_->sections();
      if (reloc_info.r_extern == 0) {
        const uint32_t sec_num = reloc_info.r_symbolnum;
        if (sec_num == R_ABS) {
          // TODO(romain): Find a sample that triggers this branch ..
          const auto it_sym = memoized_symbols_by_address_.find(reloc_info.r_address);
          if (it_sym != std::end(memoized_symbols_by_address_)) {
            reloc->symbol_ = it_sym->second;
          } else {
            LIEF_WARN("Can't find memoized symbol for the address: 0x{:x}", reloc_info.r_address);
          }
        }
        else if (sec_num < sections.size()) {
          Section& relsec = sections[reloc_info.r_symbolnum];
          reloc->section_ = &relsec;
          LIEF_DEBUG("Section: {}", relsec.name());
        } else {
          /*
           * According to ld64-609/src/ld/parsers/macho_relocatable_file.cpp,
           * r_symbolnum can be an index that out-bounds the section tables.
           *
           * if ( reloc->r_extern() ) {
           *   [...]
           * }
           * else {
           *   parser.findTargetFromAddressAndSectionNum(contentValue, reloc->r_symbolnum(), target);
           * }
           * findTargetFromAddressAndSectionNum can fail *silently* so no need to warn the user about that
           */
          LIEF_INFO("Relocation #{:d} of {} seems corrupted: "
                    "r_symbolnum is {} sections.size(): {}",
                    i, section.name(), reloc_info.r_symbolnum, sections.size());
        }
      }
    }

    if (reloc) {
      if (!reloc->has_section()) {
        reloc->section_ = &section;
      }
      reloc->architecture_ = binary_->header().cpu_type();
      section.relocations_.push_back(std::move(reloc));
    }

    current_reloc_offset += 2 * sizeof(uint32_t);
  }
  return ok();
}

template<class MACHO_T>
ok_error_t BinaryParser::parse_dyldinfo_rebases() {
  LIEF_DEBUG("[+] LC_DYLD_INFO.rebases");
  using pint_t = typename MACHO_T::uint;

  DyldInfo* dyldinfo = binary_->dyld_info();
  if (dyldinfo == nullptr) {
    LIEF_ERR("Missing DyldInfo in the main binary");
    return make_error_code(lief_errors::not_found);
  }

  uint32_t offset = std::get<0>(dyldinfo->rebase());
  uint32_t size   = std::get<1>(dyldinfo->rebase());

  if (offset == 0 || size == 0) {
    return ok();
  }

  SegmentCommand* linkedit = binary_->segment_from_offset(offset);
  if (linkedit == nullptr) {
    LIEF_WARN("Can't find the segment that contains the rebase opcodes");
    return make_error_code(lief_errors::not_found);
  }

  span<uint8_t> content = linkedit->writable_content();
  const uint64_t rel_offset = offset - linkedit->file_offset();
  if (rel_offset > content.size() || (rel_offset + size) > content.size()) {
    LIEF_ERR("Rebase opcodes are out of bounds of the segment {}", linkedit->name());
    return make_error_code(lief_errors::read_out_of_bound);
  }

  dyldinfo->rebase_opcodes_ = content.subspan(rel_offset, size);

  uint64_t end_offset = offset + size;

  bool     done = false;
  uint8_t  type = 0;
  uint32_t segment_index = 0;
  uint64_t segment_offset = 0;
  uint32_t count = 0;
  uint32_t skip = 0;

  Binary::it_segments segments = binary_->segments();
  const SegmentCommand* current_segment = nullptr;

  stream_->setpos(offset);

  while (!done && stream_->pos() < end_offset) {
    auto val = stream_->read<uint8_t>();
    if (!val) {
      break;
    }
    uint8_t imm    = *val & REBASE_IMMEDIATE_MASK;
    uint8_t opcode = *val & REBASE_OPCODE_MASK;

    switch(static_cast<REBASE_OPCODES>(opcode)) {
      case REBASE_OPCODES::REBASE_OPCODE_DONE:
        {
          done = true;
          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_SET_TYPE_IMM:
        {
          type = imm;
          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        {
          auto seg_offset = stream_->read_uleb128();
          if (!seg_offset) {
            LIEF_ERR("REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: Can't read uleb128 offset");
            break;
          }
          segment_index   = imm;
          segment_offset  = *seg_offset;

          if (segment_index < segments.size()) {
            current_segment = &segments[segment_index];
          } else {
            LIEF_ERR("REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: Bad index");
            done = true;
          }

          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_ADD_ADDR_ULEB:
        {
          auto seg_offset = stream_->read_uleb128();
          if (!seg_offset) {
            LIEF_ERR("REBASE_OPCODE_ADD_ADDR_ULEB: Can't read uleb128 offset");
            break;
          }
          segment_offset += *seg_offset;
          if (current_segment == nullptr) {
            LIEF_WARN("REBASE_OPCODE_ADD_ADDR_ULEB: the current segment is null");
          }
          else if (segment_offset > current_segment->file_size()) {
            LIEF_WARN("REBASE_OPCODE_ADD_ADDR_ULEB: Bad offset (0x{:x} > 0x{:x})",
                      segment_offset, current_segment->file_size());
          }
          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
        {
          segment_offset += (imm * sizeof(pint_t));
          if (current_segment == nullptr) {
            LIEF_WARN("REBASE_OPCODE_ADD_ADDR_IMM_SCALED: the current segment is null");
          }
          else if (segment_offset > current_segment->file_size()) {
            LIEF_WARN("REBASE_OPCODE_ADD_ADDR_IMM_SCALED: Bad offset (0x{:x} > 0x{:x})",
                      segment_offset, current_segment->file_size());
          }
          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_IMM_TIMES:
        {
          for (size_t i = 0; i < imm; ++i) {
            do_rebase<MACHO_T>(type, segment_index, segment_offset, &segments);
            segment_offset += sizeof(pint_t);
            if (current_segment == nullptr) {
              LIEF_WARN("REBASE_OPCODE_DO_REBASE_IMM_TIMES: the current segment is null");
            }
            else if (segment_offset > current_segment->file_size()) {
              LIEF_WARN("REBASE_OPCODE_DO_REBASE_IMM_TIMES: Bad offset (0x{:x} > 0x{:x})",
                        segment_offset, current_segment->file_size());
            }
          }
          break;
        }
      case REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
        {
          auto uleb128_val = stream_->read_uleb128();
          if (!uleb128_val) {
            LIEF_ERR("REBASE_OPCODE_DO_REBASE_ULEB_TIMES: Can't read uleb128 count");
            break;
          }
          count = *uleb128_val;
          for (size_t i = 0; i < count; ++i) {
            if (current_segment == nullptr) {
              LIEF_WARN("REBASE_OPCODE_DO_REBASE_ULEB_TIMES: the current segment is null");
            }
            else if (segment_offset > current_segment->file_size()) {
              LIEF_WARN("REBASE_OPCODE_DO_REBASE_ULEB_TIMES: Bad offset (0x{:x} > 0x{:x})",
                        segment_offset, current_segment->file_size());
            }

            do_rebase<MACHO_T>(type, segment_index, segment_offset, &segments);
            segment_offset += sizeof(pint_t);
          }
          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
        {
          if (current_segment == nullptr) {
            LIEF_WARN("REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: the current segment is null");
          }
          else if (segment_offset > current_segment->file_size()) {
            LIEF_WARN("REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: Bad offset (0x{:x} > 0x{:x})",
                      segment_offset, current_segment->file_size());
          }
          do_rebase<MACHO_T>(type, segment_index, segment_offset, &segments);
          auto uleb128_val = stream_->read_uleb128();
          if (!uleb128_val) {
            LIEF_ERR("REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: Can't read uleb128 segment_offset");
            break;
          }
          segment_offset += *uleb128_val + sizeof(pint_t);

          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
        {
          // Count
          auto uleb128_val = stream_->read_uleb128();
          if (!uleb128_val) {
            LIEF_ERR("Can't read REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB count");
            break;
          }
          count = *uleb128_val;

          uleb128_val = stream_->read_uleb128();
          if (!uleb128_val) {
            LIEF_ERR("Can't read REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB skip");
            break;
          }
          // Skip
          skip = *uleb128_val;


          for (size_t i = 0; i < count; ++i) {
            if (current_segment == nullptr) {
              LIEF_WARN("REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: the current segment is null");
            }
            else if (segment_offset > current_segment->file_size()) {
              LIEF_WARN("REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: Bad offset (0x{:x} > 0x{:x})",
                        segment_offset, current_segment->file_size());
            }
            do_rebase<MACHO_T>(type, segment_index, segment_offset, &segments);
            segment_offset += skip + sizeof(pint_t);
          }

          break;
        }

      default:
        {
          LIEF_ERR("Unsupported opcode: 0x{:x}", static_cast<uint32_t>(opcode));
          break;
        }
    }
  }
  return ok();
}


template<class MACHO_T>
ok_error_t BinaryParser::parse_dyldinfo_binds() {
  LIEF_DEBUG("[+] LC_DYLD_INFO.bindings");

  parse_dyldinfo_generic_bind<MACHO_T>();
  parse_dyldinfo_weak_bind<MACHO_T>();
  parse_dyldinfo_lazy_bind<MACHO_T>();

  return ok();
}

// Generic bindings
// ================
template<class MACHO_T>
ok_error_t BinaryParser::parse_dyldinfo_generic_bind() {
  using pint_t = typename MACHO_T::uint;

  DyldInfo* dyldinfo = binary_->dyld_info();
  if (dyldinfo == nullptr) {
    LIEF_ERR("Missing DyldInfo in the main binary");
    return make_error_code(lief_errors::not_found);
  }

  uint32_t offset = std::get<0>(dyldinfo->bind());
  uint32_t size   = std::get<1>(dyldinfo->bind());

  if (offset == 0 || size == 0) {
    return ok();
  }

  SegmentCommand* linkedit = binary_->segment_from_offset(offset);
  if (linkedit == nullptr) {
    LIEF_WARN("Can't find the segment that contains the regular bind opcodes");
    return make_error_code(lief_errors::not_found);
  }

  span<uint8_t> content = linkedit->writable_content();
  const uint64_t rel_offset = offset - linkedit->file_offset();
  if (rel_offset > content.size() || (rel_offset + size) > content.size()) {
    LIEF_ERR("Regular bind opcodes are out of bounds of the segment {}", linkedit->name());
    return make_error_code(lief_errors::read_out_of_bound);
  }

  dyldinfo->bind_opcodes_ = content.subspan(rel_offset, size);

  uint64_t end_offset = offset + size;

  uint8_t     type = 0;
  uint8_t     segment_idx = 0;
  uint64_t    segment_offset = 0;
  std::string symbol_name;
  int         library_ordinal = 0;

  int64_t     addend = 0;
  uint32_t    count = 0;
  uint32_t    skip = 0;

  bool        is_weak_import = false;
  bool        done = false;

  size_t ordinal_table_size     = 0;
  bool use_threaded_rebase_bind = false;
  uint8_t symbol_flags          = 0;
  uint64_t start_offset         = 0;
  std::vector<ThreadedBindData> ordinal_table;

  Binary::it_segments segments = binary_->segments();
  stream_->setpos(offset);
  while (!done && stream_->pos() < end_offset) {
    auto val = stream_->read<uint8_t>();
    if (!val) {
      break;
    }
    uint8_t imm = *val & BIND_IMMEDIATE_MASK;
    auto opcode = static_cast<BIND_OPCODES>(*val & BIND_OPCODE_MASK);

    switch (opcode) {
      case BIND_OPCODES::BIND_OPCODE_DONE:
        {
          done = true;
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        {
          library_ordinal = imm;
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        {
          auto val = stream_->read_uleb128();
          if (!val) {
            LIEF_ERR("Can't read BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB uleb128 ordinal");
            break;
          }
          library_ordinal = *val;

          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        {
          // the special ordinals are negative numbers
          if (imm == 0) {
            library_ordinal = 0;
          } else {
            int8_t sign_extended = BIND_OPCODE_MASK | imm;
            library_ordinal = sign_extended;
          }
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        {
          auto str = stream_->read_string();
          if (!str) {
            LIEF_ERR("Can't read symbol name");
            break;
          }
          symbol_name = std::move(*str);
          symbol_flags = imm;

          if ((imm & BIND_SYMBOL_FLAGS_WEAK_IMPORT) != 0) {
            is_weak_import = true;
          } else {
            is_weak_import = false;
          }
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_TYPE_IMM:
        {
          type = imm;
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_ADDEND_SLEB:
        {
          auto val = stream_->read_sleb128();
          if (!val) {
            LIEF_ERR("Can't read BIND_OPCODE_SET_ADDEND_SLEB uleb128 addend");
            break;
          }
          addend = *val;
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        {
          auto val = stream_->read_uleb128();
          if (!val) {
            LIEF_ERR("Can't read BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB uleb128 segment offset");
            break;
          }
          segment_idx    = imm;
          segment_offset = *val;
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_ADD_ADDR_ULEB:
        {
          auto val = stream_->read_uleb128();
          if (!val) {
            LIEF_ERR("Can't read BIND_OPCODE_ADD_ADDR_ULEB uleb128 segment offset");
            break;
          }
          segment_offset += *val;
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_DO_BIND:
        {
          if (!use_threaded_rebase_bind) {
            do_bind<MACHO_T>(
                BINDING_CLASS::BIND_CLASS_STANDARD,
                type,
                segment_idx,
                segment_offset,
                symbol_name,
                library_ordinal,
                addend,
                is_weak_import,
                false,
                &segments, start_offset);
            start_offset = stream_->pos() - offset + 1;
            segment_offset += sizeof(pint_t);
          } else {
            ordinal_table.push_back(ThreadedBindData{symbol_name, addend, library_ordinal, symbol_flags, type});
          }
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        {
          do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_STANDARD,
              type,
              segment_idx,
              segment_offset,
              symbol_name,
              library_ordinal,
              addend,
              is_weak_import,
              false,
              &segments, start_offset);
          start_offset = stream_->pos() - offset + 1;

          auto val = stream_->read_uleb128();
          if (!val) {
            LIEF_ERR("Can't read BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB uleb128 segment offset");
            break;
          }

          segment_offset += *val + sizeof(pint_t);
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        {
          do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_STANDARD,
              type,
              segment_idx,
              segment_offset,
              symbol_name,
              library_ordinal,
              addend,
              is_weak_import,
              false,
              &segments, start_offset);
          start_offset = stream_->pos() - offset + 1;
          segment_offset += imm * sizeof(pint_t) + sizeof(pint_t);
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
        {
          auto val = stream_->read_uleb128();
          if (!val) {
            LIEF_ERR("Can't read BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB uleb128 count");
            break;
          }
          count = *val;

          val = stream_->read_uleb128();
          if (!val) {
            LIEF_ERR("Can't read BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB uleb128 skip");
            break;
          }
          skip = *val;

          for (size_t i = 0; i < count; ++i) {
            do_bind<MACHO_T>(
                BINDING_CLASS::BIND_CLASS_STANDARD,
                type,
                segment_idx,
                segment_offset,
                symbol_name,
                library_ordinal,
                addend,
                is_weak_import,
                false,
                &segments, start_offset);
            start_offset = stream_->pos() - offset + 1;
            segment_offset += skip + sizeof(pint_t);
          }
          break;
        }
      case BIND_OPCODES::BIND_OPCODE_THREADED:
        {
          const auto subopcode = static_cast<BIND_SUBOPCODE_THREADED>(imm);
          switch (subopcode) {
            case BIND_SUBOPCODE_THREADED::BIND_SUBOPCODE_THREADED_APPLY:
              {
                uint64_t delta = 0;
                if (segment_idx >= segments.size()) {
                  LIEF_ERR("Wrong index ({:d})", segment_idx);
                  return make_error_code(lief_errors::corrupted);
                }
                const SegmentCommand& current_segment = segments[segment_idx];
                do {
                  const uint64_t address = current_segment.virtual_address() + segment_offset;
                  span<const uint8_t> content = current_segment.content();
                  if (segment_offset >= content.size() || segment_offset + sizeof(uint64_t) >= content.size()) {
                    LIEF_WARN("Bad segment offset (0x{:x})", segment_offset);
                    delta = 0; // exit from de do ... while
                    break;
                  }
                  auto value = *reinterpret_cast<const uint64_t*>(content.data() + segment_offset);
                  bool is_rebase = (value & (static_cast<uint64_t>(1) << 62)) == 0;

                  if (is_rebase) {
                    //LIEF_WARN("do rebase for addr: 0x{:x} vs 0x{:x}", address, current_segment)
                    do_rebase<MACHO_T>(static_cast<uint8_t>(REBASE_TYPES::REBASE_TYPE_POINTER),
                                       segment_idx, segment_offset, &segments);
                  } else {
                    uint16_t ordinal = value & 0xFFFF;
                    if (ordinal >= ordinal_table_size || ordinal >= ordinal_table.size()) {
                      LIEF_WARN("bind ordinal ({:d}) is out of range (max={:d}) for disk pointer 0x{:04x} in "
                                "segment '{}' (segment offset: 0x{:04x})", ordinal, ordinal_table_size, value,
                                current_segment.name(), segment_offset);
                      break;
                    }
                    if (address < current_segment.virtual_address() ||
                        address >= (current_segment.virtual_address() + current_segment.virtual_size())) {
                      LIEF_WARN("Bad binding address");
                      break;
                    }
                    const ThreadedBindData& th_bind_data = ordinal_table[ordinal];
                    do_bind<MACHO_T>(
                        BINDING_CLASS::BIND_CLASS_THREADED,
                        th_bind_data.type,
                        segment_idx,
                        segment_offset,
                        th_bind_data.symbol_name,
                        th_bind_data.library_ordinal,
                        th_bind_data.addend,
                        th_bind_data.symbol_flags & BIND_SYMBOL_FLAGS_WEAK_IMPORT,
                        false,
                        &segments, start_offset);
                        start_offset = stream_->pos() - offset + 1;
                  }
                  // The delta is bits [51..61]
                  // And bit 62 is to tell us if we are a rebase (0) or bind (1)
                  value &= ~(1ull << 62);
                  delta = (value & 0x3FF8000000000000) >> 51;
                  segment_offset += delta * sizeof(pint_t);
                } while (delta != 0);
                break;
              }
            case BIND_SUBOPCODE_THREADED::BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB:
              {
                // Maxium number of elements according to dyld's MachOAnalyzer.cpp
                static constexpr size_t MAX_COUNT = 65535;
                auto val = stream_->read_uleb128();
                if (!val) {
                  LIEF_ERR("Can't read BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB count");
                  break;
                }
                count = *val;
                if (count > MAX_COUNT) {
                  LIEF_ERR("BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB"
                           "count is too large ({})", count);
                  break;
                }
                ordinal_table_size = count + 1; // the +1 comes from: 'ld64 wrote the wrong value here and we need to offset by 1 for now.'
                use_threaded_rebase_bind = true;
                ordinal_table.reserve(ordinal_table_size);
                break;
              }
          }
          break;
        }
      default:
        {
          LIEF_ERR("Unsupported opcode: 0x{:x}", static_cast<uint32_t>(opcode));
          break;
        }
      }
  }
  dyldinfo->binding_encoding_version_ = use_threaded_rebase_bind ?
                                        DyldInfo::BINDING_ENCODING_VERSION::V2 :
                                        DyldInfo::BINDING_ENCODING_VERSION::V1;
  return ok();
}

// Weak binding
// ============
template<class MACHO_T>
ok_error_t BinaryParser::parse_dyldinfo_weak_bind() {
  using pint_t = typename MACHO_T::uint;

  DyldInfo* dyldinfo = binary_->dyld_info();
  if (dyldinfo == nullptr) {
    LIEF_ERR("Missing DyldInfo in the main binary");
    return make_error_code(lief_errors::not_found);
  }

  uint32_t offset = std::get<0>(dyldinfo->weak_bind());
  uint32_t size   = std::get<1>(dyldinfo->weak_bind());

  if (offset == 0 || size == 0) {
    return ok();
  }

  SegmentCommand* linkedit = binary_->segment_from_offset(offset);
  if (linkedit == nullptr) {
    LIEF_WARN("Can't find the segment that contains the weak bind opcodes");
    return make_error_code(lief_errors::not_found);
  }

  span<uint8_t> content = linkedit->writable_content();
  const uint64_t rel_offset = offset - linkedit->file_offset();
  if (rel_offset > content.size() || (rel_offset + size) > content.size()) {
    LIEF_ERR("Weak bind opcodes are out of bounds of the segment {}", linkedit->name());
    return make_error_code(lief_errors::read_out_of_bound);
  }

  dyldinfo->weak_bind_opcodes_ = content.subspan(rel_offset, size);

  uint64_t end_offset = offset + size;

  uint8_t     type = 0;
  uint8_t     segment_idx = 0;
  uint64_t    segment_offset = 0;
  std::string symbol_name;

  int64_t     addend = 0;
  uint32_t    count = 0;
  uint32_t    skip = 0;

  bool        is_weak_import = true;
  bool        is_non_weak_definition = false;
  bool        done = false;
  uint64_t    start_offset    = 0;

  Binary::it_segments segments = binary_->segments();

  stream_->setpos(offset);

  while (!done && stream_->pos() < end_offset) {
    auto val = stream_->read<uint8_t>();
    if (!val) {
      break;
    }
    uint8_t imm = *val & BIND_IMMEDIATE_MASK;
    auto opcode = static_cast<BIND_OPCODES>(*val & BIND_OPCODE_MASK);

    switch (opcode) {
      case BIND_OPCODES::BIND_OPCODE_DONE:
        {
          done = true;
          break;
        }


      case BIND_OPCODES::BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        {
          auto str = stream_->read_string();
          if (!str) {
            LIEF_ERR("Can't read BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM symbol name");
            break;
          }
          symbol_name = std::move(*str);

          if ((imm & BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION) != 0) {
            is_non_weak_definition = true;
          } else {
            is_non_weak_definition = false;
          }
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_TYPE_IMM:
        {
          type = imm;
          break;
        }


      case BIND_OPCODES::BIND_OPCODE_SET_ADDEND_SLEB:
        {
          auto val = stream_->read_sleb128();
          if (!val) {
            LIEF_ERR("Can't read BIND_OPCODE_SET_ADDEND_SLEB sleb128 addend");
            break;
          }
          addend = *val;
          break;
        }


      case BIND_OPCODES::BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        {
          auto val = stream_->read_uleb128();
          if (!val) {
            LIEF_ERR("Can't read BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB uleb128 segment offset");
            break;
          }
          segment_idx    = imm;
          segment_offset = *val;

          break;
        }


      case BIND_OPCODES::BIND_OPCODE_ADD_ADDR_ULEB:
        {
          auto val = stream_->read_uleb128();
          if (!val) {
            LIEF_ERR("Can't read BIND_OPCODE_ADD_ADDR_ULEB uleb128 segment offset");
            break;
          }
          segment_offset += *val;
          break;
        }


      case BIND_OPCODES::BIND_OPCODE_DO_BIND:
        {
          do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_WEAK,
              type,
              segment_idx,
              segment_offset,
              symbol_name,
              0,
              addend,
              is_weak_import,
              is_non_weak_definition,
              &segments, start_offset);
          start_offset = stream_->pos() - offset + 1;
          segment_offset += sizeof(pint_t);
          break;
        }


      case BIND_OPCODES::BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        {
          do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_WEAK,
              type,
              segment_idx,
              segment_offset,
              symbol_name,
              0,
              addend,
              is_weak_import,
              is_non_weak_definition,
              &segments, start_offset);
          start_offset = stream_->pos() - offset + 1;

          auto val = stream_->read_uleb128();
          if (!val) {
            LIEF_ERR("Can't read BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB uleb128 segment offset");
            break;
          }
          segment_offset += *val + sizeof(pint_t);
          break;
        }


      case BIND_OPCODES::BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        {
          do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_WEAK,
              type,
              segment_idx,
              segment_offset,
              symbol_name,
              0,
              addend,
              is_weak_import,
              is_non_weak_definition,
              &segments, start_offset);
          start_offset = stream_->pos() - offset + 1;
          segment_offset += imm * sizeof(pint_t) + sizeof(pint_t);
          break;
        }


      case BIND_OPCODES::BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
        {
          auto val = stream_->read_uleb128();
          if (!val) {
            LIEF_ERR("Can't read BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB uleb128 count");
            break;
          }
          // Count
          count = *val;

          // Skip
          val = stream_->read_uleb128();
          if (!val) {
            LIEF_ERR("Can't read BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB uleb128 skip");
            break;
          }
          skip = *val;

          for (size_t i = 0; i < count; ++i) {
            do_bind<MACHO_T>(
                BINDING_CLASS::BIND_CLASS_WEAK,
                type,
                segment_idx,
                segment_offset,
                symbol_name,
                0,
                addend,
                is_weak_import,
                is_non_weak_definition,
                &segments, start_offset);
            start_offset = stream_->pos() - offset + 1;
            segment_offset += skip + sizeof(pint_t);
          }
          break;
        }



      default:
        {
          LIEF_ERR("Unsupported opcode: 0x{:x}", static_cast<uint32_t>(opcode));
          break;
        }
      }
  }
  return ok();
}

// Lazy binding
// ============
template<class MACHO_T>
ok_error_t BinaryParser::parse_dyldinfo_lazy_bind() {
  using pint_t = typename MACHO_T::uint;

  DyldInfo* dyldinfo = binary_->dyld_info();
  if (dyldinfo == nullptr) {
    LIEF_ERR("Missing DyldInfo in the main binary");
    return make_error_code(lief_errors::not_found);
  }

  uint32_t offset = std::get<0>(dyldinfo->lazy_bind());
  uint32_t size   = std::get<1>(dyldinfo->lazy_bind());

  if (offset == 0 || size == 0) {
    return ok();
  }

  SegmentCommand* linkedit = binary_->segment_from_offset(offset);
  if (linkedit == nullptr) {
    LIEF_WARN("Can't find the segment that contains the lazy bind opcodes");
    return make_error_code(lief_errors::not_found);
  }

  span<uint8_t> content = linkedit->writable_content();
  const uint64_t rel_offset = offset - linkedit->file_offset();
  if (rel_offset > content.size() || (rel_offset + size) > content.size()) {
    LIEF_ERR("Lazy bind opcodes are out of bounds of the segment {}", linkedit->name());
    return make_error_code(lief_errors::read_out_of_bound);
  }

  dyldinfo->lazy_bind_opcodes_ = content.subspan(rel_offset, size);

  uint64_t end_offset = offset + size;

  //uint32_t    lazy_offset     = 0;
  std::string symbol_name;
  uint8_t     segment_idx     = 0;
  uint64_t    segment_offset  = 0;
  int32_t     library_ordinal = 0;
  int64_t     addend          = 0;
  bool        is_weak_import  = false;
  uint64_t    start_offset    = 0;

  Binary::it_segments segments = binary_->segments();
  stream_->setpos(offset);
  while (stream_->pos() < end_offset) {
    auto val = stream_->read<uint8_t>();
    if (!val) {
      break;
    }
    uint8_t imm = *val & BIND_IMMEDIATE_MASK;
    auto opcode = static_cast<BIND_OPCODES>(*val & BIND_OPCODE_MASK);

    switch (opcode) {
      case BIND_OPCODES::BIND_OPCODE_DONE:
        {
          //lazy_offset = current_offset - offset;
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        {
          library_ordinal = imm;
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        {
          auto val = stream_->read_uleb128();
          if (!val) {
            LIEF_ERR("Can't read BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB uleb128 library ordinal");
            break;
          }

          library_ordinal = *val;
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        {
          // the special ordinals are negative numbers
          if (imm == 0) {
            library_ordinal = 0;
          } else {
            int8_t sign_extended = BIND_OPCODE_MASK | imm;
            library_ordinal = sign_extended;
          }
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        {
          auto str = stream_->read_string();
          if (!str) {
            LIEF_ERR("Can't read symbol name");
            break;
          }
          symbol_name = std::move(*str);

          if ((imm & BIND_SYMBOL_FLAGS_WEAK_IMPORT) != 0) {
            is_weak_import = true;
          } else {
            is_weak_import = false;
          }
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_ADDEND_SLEB:
        {
          auto val = stream_->read_sleb128();
          if (!val) {
            LIEF_ERR("Can't read BIND_OPCODE_SET_ADDEND_SLEB sleb128 addend");
            break;
          }
          addend = *val;
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        {
          auto val = stream_->read_uleb128();
          if (!val) {
            LIEF_ERR("Can't read BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB uleb128 segment offset");
            break;
          }
          segment_idx    = imm;
          segment_offset = *val;

          break;
        }

      case BIND_OPCODES::BIND_OPCODE_DO_BIND:
        {
          do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_LAZY,
              static_cast<uint8_t>(BIND_TYPES::BIND_TYPE_POINTER),
              segment_idx,
              segment_offset,
              symbol_name,
              library_ordinal,
              addend,
              is_weak_import,
              false,
              &segments, start_offset);
          start_offset = stream_->pos() - offset + 1;
          segment_offset += sizeof(pint_t);
          break;
        }

      default:
        {
          LIEF_ERR("Unsupported opcode: 0x{:x}", static_cast<uint32_t>(opcode));
          break;
        }
      }
  }
  return ok();
}

template<class MACHO_T>
ok_error_t BinaryParser::do_bind(BINDING_CLASS cls,
                                 uint8_t type,
                                 uint8_t segment_idx,
                                 uint64_t segment_offset,
                                 const std::string& symbol_name,
                                 int32_t ord,
                                 int64_t addend,
                                 bool is_weak,
                                 bool is_non_weak_definition,
                                 it_opaque_segments segments_ptr,
                                 uint64_t offset)
{
  auto& segments = *static_cast<Binary::it_segments*>(segments_ptr);
  if (segment_idx >= segments.size()) {
    LIEF_ERR("Wrong index: {:d}", segment_idx);
    return make_error_code(lief_errors::corrupted);
  }
  SegmentCommand& segment = segments[segment_idx];
  // Address to bind
  uint64_t address = segment.virtual_address() + segment_offset;

  if (address > (segment.virtual_address() + segment.virtual_size())) {
    LIEF_ERR("Bad address: 0x{:x}", address);
    return make_error_code(lief_errors::corrupted);
  }


  // Create a BindingInfo object
  auto binding_info = std::make_unique<DyldBindingInfo>(
      cls, static_cast<BIND_TYPES>(type), address, addend, ord, is_weak,
      is_non_weak_definition, offset);

  binding_info->segment_ = &segment;


  if (0 < ord && static_cast<size_t>(ord) <= binding_libs_.size()) {
    binding_info->library_ = binding_libs_[ord - 1];
  }

  Symbol* symbol = nullptr;
  auto search = memoized_symbols_.find(symbol_name);
  if (search != memoized_symbols_.end()) {
    symbol = search->second;
  } else {
    symbol = binary_->get_symbol(symbol_name);
  }
  if (symbol != nullptr) {
    binding_info->symbol_ = symbol;
    symbol->binding_info_ = binding_info.get();
  } else {
    LIEF_INFO("New symbol discovered: {}", symbol_name);
    auto symbol = std::make_unique<Symbol>();
    symbol->origin_            = SYMBOL_ORIGINS::SYM_ORIGIN_DYLD_BIND;
    symbol->type_              = 0;
    symbol->numberof_sections_ = 0;
    symbol->description_       = 0;
    symbol->name(symbol_name);

    binding_info->symbol_ = symbol.get();
    symbol->binding_info_ = binding_info.get();
    binary_->symbols_.push_back(std::move(symbol));
  }

  DyldInfo* dyld_info = binary_->dyld_info();
  if (dyld_info == nullptr) {
    LIEF_ERR("Missing DyldInfo in the main binary");
    return make_error_code(lief_errors::not_found);
  }
  dyld_info->binding_info_.push_back(std::move(binding_info));
  LIEF_DEBUG("{} {} - {}", to_string(cls), segment.name(), symbol_name);
  return ok();
}

template<class MACHO_T>
ok_error_t BinaryParser::do_rebase(uint8_t type, uint8_t segment_idx, uint64_t segment_offset,
                                   const it_opaque_segments segments_ptr) {

  const auto& segments = *static_cast<const Binary::it_segments*>(segments_ptr);

  using pint_t = typename MACHO_T::uint;

  if (segment_idx >= segments.size()) {
    LIEF_ERR("Wrong index ({:d})", segment_idx);
    return make_error_code(lief_errors::corrupted);
  }

  SegmentCommand& segment = segments[segment_idx];
  uint64_t address = segment.virtual_address() + segment_offset;

  if (address > (segment.virtual_address() + segment.virtual_size())) {
    LIEF_ERR("Bad rebase address: 0x{:x}", address);
    return make_error_code(lief_errors::corrupted);
  }

  auto reloc = std::make_unique<RelocationDyld>(address, type);

  // result.second is true if the insertion succeed
  reloc->architecture_ = binary_->header().cpu_type();

  // Tie section and segment
  reloc->segment_ = &segment;
  Section* section = binary_->section_from_virtual_address(address);
  if (section == nullptr) {
    LIEF_ERR("Can't find the section associated with the virtual address 0x{:x}", address);
    return make_error_code(lief_errors::not_found);
  }
  reloc->section_ = section;

  // Tie symbol
  const auto it_symbol = memoized_symbols_by_address_.find(address);
  if (it_symbol != memoized_symbols_by_address_.end()) {
    reloc->symbol_ = it_symbol->second;
  }

  switch (static_cast<REBASE_TYPES>(type)) {
    case REBASE_TYPES::REBASE_TYPE_POINTER:
      {
        reloc->size_ = sizeof(pint_t) * BYTE_BITS;
        break;
      }


    case REBASE_TYPES::REBASE_TYPE_TEXT_ABSOLUTE32:
    case REBASE_TYPES::REBASE_TYPE_TEXT_PCREL32:
      {
        reloc->size_ = sizeof(uint32_t) * BYTE_BITS;
        break;
      }

    case REBASE_TYPES::REBASE_TYPE_THREADED:
      {
        reloc->size_ = sizeof(pint_t) * BYTE_BITS;
        break;
      }

    default:
      {
        LIEF_ERR("Unsuported relocation type: 0x{:x}", type);
      }
  }
  // Check if a relocation already exists:
  if (dyld_reloc_addrs_.insert(address).second) {
    segment.relocations_.push_back(std::move(reloc));
  } else {
    LIEF_DEBUG("[!] Duplicated symbol address in the dyld rebase: 0x{:x}", address);
  }
  return ok();
}


template<class MACHO_T>
ok_error_t BinaryParser::parse_chained_payload(SpanStream& stream) {
  details::dyld_chained_fixups_header header;

  if (auto res = stream.peek<details::dyld_chained_fixups_header>()) {
    header = *res;
  } else {
    LIEF_WARN("Can't read dyld_chained_fixups_header: {}", get_error(res).message());
    return make_error_code(lief_errors::read_error);
  }

  LIEF_DEBUG("fixups_version = {}", header.fixups_version);
  LIEF_DEBUG("starts_offset  = {}", header.starts_offset);
  LIEF_DEBUG("imports_offset = {}", header.imports_offset);
  LIEF_DEBUG("symbols_offset = {}", header.symbols_offset);
  LIEF_DEBUG("imports_count  = {}", header.imports_count);
  LIEF_DEBUG("imports_format = {} ({})", header.imports_format,
                                         to_string(static_cast<DYLD_CHAINED_FORMAT>(header.imports_format)));
  LIEF_DEBUG("symbols_format = {}", header.symbols_format);
  chained_fixups_->update_with(header);

  auto res_symbols_pools = stream.slice(header.symbols_offset);
  if (!res_symbols_pools) {
    LIEF_WARN("Can't access the symbols pools (dyld_chained_fixups_header.symbols_offset)");
    return make_error_code(lief_errors::read_error);
  }

  SpanStream symbols_pool = std::move(*res_symbols_pools);
  if (!parse_chained_import<MACHO_T>(header, stream, symbols_pool)) {
    LIEF_WARN("Error while parsing the chained imports");
    return make_error_code(lief_errors::parsing_error);
  }
  if (!parse_chained_fixup<MACHO_T>(header, stream)) {
    LIEF_WARN("Error while parsing the chained fixup");
    return make_error_code(lief_errors::parsing_error);
  }
  return ok();
}


template<class MACHO_T>
ok_error_t BinaryParser::parse_chained_import(const details::dyld_chained_fixups_header& header,
                                              SpanStream& stream, SpanStream& symbol_pool) {

  // According to validChainedFixupsInfo for the cases of
  // DYLD_CHAINED_PTR_64 / DYLD_CHAINED_PTR_64_OFFSET / DYLD_CHAINED_PTR_ARM64E_USERLAND24
  static constexpr uint32_t MAX_BIND_ORDINAL = 0xFFFFFF;


  // Sanity checks according to dyld-852.2 / MachOAnalyzer.cpp:forEachChainedFixupTarget
  if (header.imports_offset > stream.size() || header.symbols_offset > stream.size()) {
    LIEF_WARN("Malformed LC_DYLD_CHAINED_FIXUPS: "
              "dyld_chained_fixups_header.{{imports_offset, symbols_offset}} are out of ranges");
    return make_error_code(lief_errors::parsing_error);
  }

  if (header.imports_count >= MAX_BIND_ORDINAL) {
    LIEF_WARN("dyld_chained_fixups_header.imports_count is too large: {}. It should at most {}",
              header.imports_count, MAX_BIND_ORDINAL);
    return make_error_code(lief_errors::parsing_error);
  }

  const auto fmt = static_cast<DYLD_CHAINED_FORMAT>(header.imports_format);
  switch (fmt) {
    case DYLD_CHAINED_FORMAT::IMPORT:
      {
        stream.setpos(header.imports_offset);
        for (size_t i = 0; i < header.imports_count; ++i) {
          details::dyld_chained_import import;
          std::string symbol_name;
          if (auto res = stream.read<details::dyld_chained_import>()) {
            import = *res;
          } else {
            LIEF_WARN("Can't read dyld_chained_import #{}: {}", i, get_error(res).message());
            break;
          }
          LIEF_DEBUG("dyld chained import[{}]", i);
          if (auto res = symbol_pool.peek_string_at(import.name_offset)) {
            symbol_name = std::move(*res);
          } else {
            LIEF_WARN("Can't read dyld_chained_import.name #{}: {}", i, get_error(res).message());
            break;
          }
          int32_t lib_ordinal = 0;
          uint8_t lib_val = import.lib_ordinal;
          if (lib_val > 0xF0) {
            lib_ordinal = static_cast<int8_t>(lib_val);
          } else {
            lib_ordinal = lib_val;
          }
          do_fixup<MACHO_T>(fmt, lib_ordinal, symbol_name, 0, import.weak_import);
        }
        break;
      }
    case DYLD_CHAINED_FORMAT::IMPORT_ADDEND:
      {
        stream.setpos(header.imports_offset);
        for (size_t i = 0; i < header.imports_count; ++i) {
          details::dyld_chained_import_addend import;
          std::string symbol_name;
          if (auto res = stream.read<details::dyld_chained_import_addend>()) {
            import = *res;
          } else {
            LIEF_WARN("Can't read dyld_chained_import_addend #{}: {}", i, get_error(res).message());
            break;
          }
          if (auto res = symbol_pool.peek_string_at(import.name_offset)) {
            symbol_name = std::move(*res);
          } else {
            LIEF_WARN("Can't read dyld_chained_import_addend.name #{}: {}", i, get_error(res).message());
            break;
          }
          int32_t lib_ordinal = 0;
          uint8_t lib_val = import.lib_ordinal;
          if (lib_val > 0xF0) {
            lib_ordinal = static_cast<int8_t>(lib_val);
          } else {
            lib_ordinal = lib_val;
          }
          do_fixup<MACHO_T>(fmt, lib_ordinal, symbol_name, import.addend, import.weak_import);
        }
        break;
      }
    case DYLD_CHAINED_FORMAT::IMPORT_ADDEND64:
      {
        stream.setpos(header.imports_offset);
        for (size_t i = 0; i < header.imports_count; ++i) {
          details::dyld_chained_import_addend64 import;
          std::string symbol_name;
          if (auto res = stream.read<details::dyld_chained_import_addend64>()) {
            import = *res;
          } else {
            LIEF_WARN("Can't read dyld_chained_import_addend64 #{}: {}", i, get_error(res).message());
            break;
          }
          if (auto res = symbol_pool.peek_string_at(import.name_offset)) {
            symbol_name = std::move(*res);
          } else {
            LIEF_WARN("Can't read dyld_chained_import_addend64.name #{}: {}", i, get_error(res).message());
            break;
          }
          int32_t lib_ordinal = 0;
          uint16_t lib_val = import.lib_ordinal;
          if (lib_val > 0xFFF0) {
            lib_ordinal = static_cast<int16_t>(lib_val);
          } else {
            lib_ordinal = lib_val;
          }
          do_fixup<MACHO_T>(fmt, lib_ordinal, symbol_name, import.addend, import.weak_import);
        }
        break;
      }
    default:
      {
        LIEF_WARN("Dyld Chained Fixups: {} is an unknown format", header.imports_format);
      }
  }
  return ok();
}

template<class MACHO_T>
ok_error_t BinaryParser::parse_chained_fixup(const details::dyld_chained_fixups_header& header,
                                             SpanStream& stream)
{
  details::dyld_chained_starts_in_image starts;
  stream.setpos(header.starts_offset);
  if (auto res = stream.read<details::dyld_chained_starts_in_image>()) {
    starts = *res;
  } else {
    LIEF_WARN("Can't read dyld_chained_starts_in_image: {}", get_error(res).message());
    return res.error();
  }

  LIEF_DEBUG("chained starts in image");
  LIEF_DEBUG("  seg_count = {}", starts.seg_count);

  uint32_t nb_segments = starts.seg_count;
  if (nb_segments > binary_->segments_.size()) {
    LIEF_WARN("Chained fixup: dyld_chained_starts_in_image.seg_count ({}) "
              "exceeds the number of segments ({})", starts.seg_count, binary_->segments_.size());
    nb_segments = binary_->segments_.size();
  }

  for (uint32_t seg_idx = 0; seg_idx < nb_segments; ++seg_idx) {
    uint32_t seg_info_offset = 0;
    if (auto res = stream.read<uint32_t>()) {
      seg_info_offset = *res;
    } else {
      LIEF_WARN("Can't read dyld_chained_starts_in_image.seg_info_offset[#{}]: {}",
                seg_idx, get_error(res).message());
      break;
    }

    LIEF_DEBUG("    seg_offset[{}] = {} ({})", seg_idx, seg_info_offset, binary_->segments_[seg_idx]->name());
    if (seg_info_offset == 0) {
      struct DyldChainedFixups::chained_starts_in_segment info(0, {}, *binary_->segments_[seg_idx]);
      chained_fixups_->chained_starts_in_segment_.push_back(std::move(info));
      continue;
    }
    LIEF_DEBUG("    #{} processing dyld_chained_starts_in_segment", seg_idx);
    const uint64_t offset = header.starts_offset + seg_info_offset;
    if (!parse_fixup_seg<MACHO_T>(stream, seg_info_offset, offset, seg_idx)) {
      LIEF_WARN("Error while parsing fixup in segment: {}", binary_->segments_[seg_idx]->name());
    }
  }

  return ok();
}

template<class MACHO_T>
ok_error_t BinaryParser::parse_fixup_seg(SpanStream& stream, uint32_t seg_info_offset,
                                         uint64_t offset, uint32_t seg_idx)
{
  static constexpr const char DPREFIX[] = "    ";
  static constexpr auto DYLD_CHAINED_PTR_START_NONE  = 0xFFFF;
  static constexpr auto DYLD_CHAINED_PTR_START_MULTI = 0x8000;
  static constexpr auto DYLD_CHAINED_PTR_START_LAST  = 0x8000;

  details::dyld_chained_starts_in_segment seg_info;
  if (auto res = stream.peek<decltype(seg_info)>(offset)) {
    seg_info = *res;
  } else {
    LIEF_WARN("Can't read dyld_chained_starts_in_segment for #{}: {}", seg_idx, get_error(res).message());
    return res.error();
  }
  auto res_seg_stream = stream.slice(offset);
  if (!res_seg_stream) {
    LIEF_ERR("Can't slice dyld_chained_starts_in_segment #{}: {}",
              seg_idx, get_error(res_seg_stream).message());
    return res_seg_stream.error();
  }
  SpanStream seg_stream = std::move(*res_seg_stream);
  seg_stream.read<details::dyld_chained_starts_in_segment>();

  LIEF_DEBUG("{}size              = {}",      DPREFIX, seg_info.size);
  LIEF_DEBUG("{}page_size         = 0x{:x}",  DPREFIX, seg_info.page_size);
  LIEF_DEBUG("{}pointer_format    = {} ({})", DPREFIX, seg_info.pointer_format, to_string(static_cast<DYLD_CHAINED_PTR_FORMAT>(seg_info.pointer_format)));
  LIEF_DEBUG("{}segment_offset    = 0x{:x}",  DPREFIX, seg_info.segment_offset);
  LIEF_DEBUG("{}max_valid_pointer = {}",      DPREFIX, seg_info.max_valid_pointer);
  LIEF_DEBUG("{}page_count        = {}",      DPREFIX, seg_info.page_count);

  SegmentCommand* segment = binary_->segments_[seg_idx];

  struct DyldChainedFixups::chained_starts_in_segment info(seg_info_offset, seg_info, *segment);
  info.page_start.reserve(10);
  const uint64_t page_start_off = seg_stream.pos();
  for (uint32_t page_idx = 0; page_idx < seg_info.page_count; ++page_idx) {
    uint16_t offset_in_page = 0;
    if (auto res = seg_stream.read<decltype(offset_in_page)>()) {
      offset_in_page = *res;
    } else {
      LIEF_WARN("Can't read dyld_chained_starts_in_segment.page_start[{}]", page_idx);
      break;
    }
    info.page_start.push_back(offset_in_page);

    LIEF_DEBUG("{}    page_start[{}]: {}", DPREFIX, page_idx, offset_in_page);

    if (offset_in_page == DYLD_CHAINED_PTR_START_NONE) {
      continue;
    }

    if ((offset_in_page & DYLD_CHAINED_PTR_START_MULTI) > 0) {
      uint32_t overflow_index = offset_in_page & ~DYLD_CHAINED_PTR_START_MULTI;
      bool chain_end = false;
      while (!chain_end) {
        uint16_t overflow_val = 0;
        const uint64_t off = page_start_off + overflow_index * sizeof(uint16_t); // &segInfo->page_start[overflowIndex]
        if (auto res = seg_stream.peek<decltype(overflow_val)>(off)) {
          overflow_val = *res;
        } else {
          LIEF_WARN("Can't read page_start[overflow_index: {}]", overflow_index);
          break;
        }
        chain_end      = overflow_val & DYLD_CHAINED_PTR_START_LAST;
        offset_in_page = overflow_val & ~DYLD_CHAINED_PTR_START_LAST;
        uint64_t page_content_start = seg_info.segment_offset + (page_idx * seg_info.page_size);
        uint64_t chain_offset = page_content_start + offset_in_page;
        auto is_ok = walk_chain<MACHO_T>(*segment, chain_offset, seg_info);
        if (!is_ok) {
          LIEF_WARN("Error while walking through the chained fixup of the segment '{}'", segment->name());
        }
        ++overflow_index;
      }

    } else {
      uint64_t page_content_start = seg_info.segment_offset + (page_idx * seg_info.page_size);
      uint64_t chain_offset = page_content_start + offset_in_page;
      auto is_ok = walk_chain<MACHO_T>(*segment, chain_offset, seg_info);
      if (!is_ok) {
        LIEF_WARN("Error while walking through the chained fixup of the segment '{}'", segment->name());
      }
    }
  }

  chained_fixups_->chained_starts_in_segment_.push_back(std::move(info));
  return ok();
}


template<class MACHO_T>
ok_error_t BinaryParser::do_fixup(DYLD_CHAINED_FORMAT fmt, int32_t ord, const std::string& symbol_name,
                                  int64_t addend, bool is_weak)
{
  auto binding_info = std::make_unique<ChainedBindingInfo>(fmt, is_weak);
  binding_info->addend_ = addend;
  binding_info->library_ordinal_ = ord;
  if (0 < ord && static_cast<size_t>(ord) <= binding_libs_.size()) {
    binding_info->library_ = binding_libs_[ord - 1];
    LIEF_DEBUG("  lib_ordinal: {} ({})", ord, binding_libs_[ord - 1]->name());
  } else {
    LIEF_DEBUG("  lib_ordinal: {}", ord);
  }

  LIEF_DEBUG("  weak_import: {}", is_weak);
  LIEF_DEBUG("  name:        {}", symbol_name);

  auto search = memoized_symbols_.find(symbol_name);

  Symbol* symbol = nullptr;
  if (search != std::end(memoized_symbols_)) {
    symbol = search->second;
  } else {
    symbol = binary_->get_symbol(symbol_name);
  }
  if (symbol != nullptr) {
    binding_info->symbol_ = symbol;
    symbol->binding_info_ = binding_info.get();
  } else {
    LIEF_INFO("New symbol discovered: {}", symbol_name);
    auto symbol = std::make_unique<Symbol>();
    symbol->type_              = 0;
    symbol->numberof_sections_ = 0;
    symbol->description_       = 0;
    symbol->name(symbol_name);

    binding_info->symbol_ = symbol.get();
    symbol->binding_info_ = binding_info.get();
    binary_->symbols_.push_back(std::move(symbol));
  }
  chained_fixups_->bindings_.push_back(std::move(binding_info));
  return ok();
}


template<class MACHO_T>
ok_error_t BinaryParser::walk_chain(SegmentCommand& segment, uint64_t chain_offset,
                                    const details::dyld_chained_starts_in_segment& seg_info)
{
  bool stop      = false;
  bool chain_end = false;
  while (!stop && !chain_end) {
    if (!process_fixup<MACHO_T>(segment, chain_offset, seg_info)) {
      LIEF_WARN("Error while processing the chain at offset: 0x{:x}", chain_offset);
      return make_error_code(lief_errors::parsing_error);
    }
    if (auto res = next_chain<MACHO_T>(chain_offset, seg_info)) {
      chain_offset = *res;
    } else {
      LIEF_WARN("Error while computing the next chain for the offset: 0x{:x}", chain_offset);
      return make_error_code(lief_errors::parsing_error);
    }

    if (chain_offset == 0) {
      chain_end = true;
    }
  }
  return ok();
}


inline uintptr_t stride_size(DYLD_CHAINED_PTR_FORMAT fmt) {
  switch (fmt) {
      case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E:
      case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND:
      case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND24:
        return 8;

      case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_KERNEL:
      case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_FIRMWARE:
      case DYLD_CHAINED_PTR_FORMAT::PTR_32_FIRMWARE:
      case DYLD_CHAINED_PTR_FORMAT::PTR_64:
      case DYLD_CHAINED_PTR_FORMAT::PTR_64_OFFSET:
      case DYLD_CHAINED_PTR_FORMAT::PTR_32:
      case DYLD_CHAINED_PTR_FORMAT::PTR_32_CACHE:
      case DYLD_CHAINED_PTR_FORMAT::PTR_64_KERNEL_CACHE:
          return 4;

      case DYLD_CHAINED_PTR_FORMAT::PTR_X86_64_KERNEL_CACHE:
          return 1;
  }
  return 0;
}

template<class MACHO_T>
result<uint64_t> BinaryParser::next_chain(uint64_t chain_offset,
                                          const details::dyld_chained_starts_in_segment& seg_info)
{
  const auto ptr_fmt = static_cast<DYLD_CHAINED_PTR_FORMAT>(seg_info.pointer_format);
  static constexpr uint64_t CHAIN_END = 0;
  const uintptr_t stride = stride_size(ptr_fmt);

  switch (ptr_fmt) {
    case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E:
    case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_KERNEL:
    case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND:
    case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND24:
    case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_FIRMWARE:
      {
        /* offset point to a dyld_chained_ptr_arm64e_* structure */
        details::dyld_chained_ptr_arm64e chain;
        if (auto res = stream_->peek<decltype(chain)>(chain_offset)) {
          chain = *res;
        } else {
          LIEF_ERR("Can't read the dyld chain at 0x{:x}", chain_offset);
          return res.error();
        }

        if (chain.rebase.next == 0) {
          return CHAIN_END;
        }
        return chain_offset + chain.rebase.next * stride;
      }

    case DYLD_CHAINED_PTR_FORMAT::PTR_64:
    case DYLD_CHAINED_PTR_FORMAT::PTR_64_OFFSET:
      {
        details::dyld_chained_ptr_generic64 chain;
        if (auto res = stream_->peek<decltype(chain)>(chain_offset)) {
          chain = *res;
        } else {
          LIEF_ERR("Can't read the dyld chain at 0x{:x}", chain_offset);
          return res.error();
        }

        if (chain.rebase.next == 0) {
          return CHAIN_END;
        }
        return chain_offset + chain.rebase.next * 4;
      }
    case DYLD_CHAINED_PTR_FORMAT::PTR_32:
      {
        details::dyld_chained_ptr_generic32 chain;
        if (auto res = stream_->peek<decltype(chain)>(chain_offset)) {
          chain = *res;
        } else {
          LIEF_ERR("Can't read the dyld chain at 0x{:x}", chain_offset);
          return res.error();
        }

        if (chain.rebase.next == 0) {
          return CHAIN_END;
        }
        chain_offset += chain.rebase.next * 4;

        if (auto res = stream_->peek<decltype(chain)>(chain_offset)) {
          chain = *res;
        } else {
          LIEF_ERR("Can't read the dyld chain at 0x{:x}", chain_offset);
          return CHAIN_END;
        }

        while (chain.rebase.bind == 0 && chain.rebase.target > seg_info.max_valid_pointer) {
          chain_offset += chain.rebase.next * 4;
          if (auto res = stream_->peek<decltype(chain)>(chain_offset)) {
            chain = *res;
          } else {
            LIEF_ERR("Can't read the dyld chain at 0x{:x}", chain_offset);
            return CHAIN_END;
          }
        }
        return chain_offset;
      }
    case DYLD_CHAINED_PTR_FORMAT::PTR_64_KERNEL_CACHE:
    case DYLD_CHAINED_PTR_FORMAT::PTR_X86_64_KERNEL_CACHE:
      {
        details::dyld_chained_ptr_kernel64 chain;

        if (auto res = stream_->peek<decltype(chain)>(chain_offset)) {
          chain = *res;
        } else {
          LIEF_ERR("Can't read the dyld chain at 0x{:x}", chain_offset);
          return res.error();
        }

        if (chain.next == 0) {
          return CHAIN_END;
        }
        return chain.next * stride;
      }
    case DYLD_CHAINED_PTR_FORMAT::PTR_32_FIRMWARE:
      {
        details::dyld_chained_ptr_firm32 chain;

        if (auto res = stream_->peek<decltype(chain)>(chain_offset)) {
          chain = *res;
        } else {
          LIEF_ERR("Can't read the dyld chain at 0x{:x}", chain_offset);
          return res.error();
        }

        if (chain.next == 0) {
          return CHAIN_END;
        }
        return chain.next * 4;
      }
    default:
      {
        LIEF_ERR("Unknown pointer format: 0x{:04x}", seg_info.pointer_format);
        return make_error_code(lief_errors::not_supported);
      }
  }
  return make_error_code(lief_errors::not_supported);
}


template<class MACHO_T>
ok_error_t BinaryParser::process_fixup(SegmentCommand& segment, uint64_t chain_offset,
                                       const details::dyld_chained_starts_in_segment& seg_info)
{
  const auto ptr_fmt = static_cast<DYLD_CHAINED_PTR_FORMAT>(seg_info.pointer_format);
  //LIEF_DEBUG("0x{:04x}: {}", chain_offset, to_string(ptr_fmt));
  switch (ptr_fmt) {
    case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E:
    case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_KERNEL:
    case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND:
    case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND24:
      {
        /* offset point to a dyld_chained_ptr_arm64e_* structure */
        details::dyld_chained_ptr_arm64e fixup;
        if (auto res = stream_->peek<decltype(fixup)>(chain_offset)) {
          fixup = *res;
        } else {
          LIEF_ERR("Can't read the dyld chain at 0x{:x}", chain_offset);
          return res.error();
        }

        auto is_ok = do_chained_fixup(segment, chain_offset, seg_info, fixup);
        if (!is_ok) {
          LIEF_WARN("Can't process the fixup {} - 0x{:x}", segment.name(), chain_offset);
          return is_ok.error();
        }
        return ok();
      }
    case DYLD_CHAINED_PTR_FORMAT::PTR_64:
    case DYLD_CHAINED_PTR_FORMAT::PTR_64_OFFSET:
      {
        details::dyld_chained_ptr_generic64 fixup;
        if (auto res = stream_->peek<decltype(fixup)>(chain_offset)) {
          fixup = *res;
        } else {
          LIEF_ERR("Can't read the dyld chain at 0x{:x}", chain_offset);
          return res.error();
        }
        auto is_ok = do_chained_fixup(segment, chain_offset, seg_info, fixup);
        if (!is_ok) {
          LIEF_WARN("Can't process the fixup {} - 0x{:x}", segment.name(), chain_offset);
          return is_ok.error();
        }
        return ok();
      }
    case DYLD_CHAINED_PTR_FORMAT::PTR_32:
      {
        details::dyld_chained_ptr_generic32 fixup;
        if (auto res = stream_->peek<decltype(fixup)>(chain_offset)) {
          fixup = *res;
        } else {
          LIEF_ERR("Can't read the dyld chain at 0x{:x}", chain_offset);
          return res.error();
        }
        auto is_ok = do_chained_fixup(segment, chain_offset, seg_info, fixup);
        if (!is_ok) {
          LIEF_WARN("Can't process the fixup {} - 0x{:x}", segment.name(), chain_offset);
          return is_ok.error();
        }
        return ok();
      }
    case DYLD_CHAINED_PTR_FORMAT::PTR_64_KERNEL_CACHE:
    case DYLD_CHAINED_PTR_FORMAT::PTR_X86_64_KERNEL_CACHE:
      {
        LIEF_INFO("DYLD_CHAINED_PTR_FORMAT: {} is not implemented. Please consider opening an issue with "
                  "the attached binary", to_string(ptr_fmt));
        return make_error_code(lief_errors::not_implemented);
      }
    case DYLD_CHAINED_PTR_FORMAT::PTR_32_FIRMWARE:
      {
        LIEF_INFO("DYLD_CHAINED_PTR_FORMAT: {} is not implemented. Please consider opening an issue with "
                  "the attached binary", to_string(ptr_fmt));
        return make_error_code(lief_errors::not_implemented);
      }
    default:
      {
        LIEF_ERR("Unknown pointer format: 0x{:04x}", seg_info.pointer_format);
        return make_error_code(lief_errors::not_supported);
      }
  }
  return ok();
}


/* ARM64E Fixup
 * =====================================
 */
ok_error_t BinaryParser::do_chained_fixup(SegmentCommand& segment, uint32_t chain_offset,
                                          const details::dyld_chained_starts_in_segment& seg_info,
                                          const details::dyld_chained_ptr_arm64e& fixup)
{
  static constexpr const char DPREFIX[] = "          ";
  const auto ptr_fmt = static_cast<DYLD_CHAINED_PTR_FORMAT>(seg_info.pointer_format);
  const uint64_t imagebase = binary_->imagebase();
  const uint64_t address = imagebase + chain_offset;

  if (fixup.auth_rebase.auth) {
    if (fixup.auth_bind.bind) {
      uint32_t bind_ordinal = ptr_fmt == DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND24 ?
                              fixup.auth_bind24.ordinal :
                              fixup.auth_bind.ordinal;
      if (bind_ordinal >= chained_fixups_->bindings_.size()) {
        LIEF_WARN("Out of range bind ordinal {} (max {})", bind_ordinal, chained_fixups_->bindings_.size());
        return make_error_code(lief_errors::read_error);
      }
      std::unique_ptr<ChainedBindingInfo>& binding = chained_fixups_->bindings_[bind_ordinal];
      binding->offset_          = chain_offset;
      binding->ptr_format_      = ptr_fmt;
      binding->segment_         = &segment;
      /*
       * We use the BindingInfo::address_ to store the imagebase
       * to avoid creating a new attribute in ChainedBindingInfo
       */
      binding->address_         = imagebase;
      binding->set(fixup.auth_bind);
      if (Symbol* sym = binding->symbol()) {
        LIEF_DEBUG("{}[  BIND] {}@0x{:x}: {} / sign ext: {:x}",
                   DPREFIX, segment.name(), address, sym->name(), fixup.sign_extended_addend());
        return ok();
      }
      LIEF_DEBUG("{}[  BIND] {}@0x{:x}: <missing symbol> / sign ext: {:x}",
                 DPREFIX, segment.name(), address, fixup.sign_extended_addend());
      LIEF_ERR("Missing symbol for binding at ordinal {}", bind_ordinal);
      return make_error_code(lief_errors::not_found);
    }
    const uint64_t target = imagebase + fixup.auth_rebase.target;

    auto reloc = std::make_unique<RelocationFixup>(ptr_fmt, imagebase);
    reloc->set(fixup.auth_rebase);
    reloc->architecture_ = binary_->header().cpu_type();
    reloc->segment_      = &segment;
    reloc->size_         = stride_size(ptr_fmt) * BYTE_BITS;
    reloc->offset_       = chain_offset;

    if (Section* section = binary_->section_from_virtual_address(address)) {
      reloc->section_ = section;
    } else {
      LIEF_ERR("Can't find the section associated with the virtual address 0x{:x}", address);
    }

    const auto it_symbol = memoized_symbols_by_address_.find(address);
    if (it_symbol != memoized_symbols_by_address_.end()) {
      reloc->symbol_ = it_symbol->second;
    }

    LIEF_DEBUG("{}[REBASE] {}@0x{:x}: 0x{:x}",
               DPREFIX, segment.name(), address, target);

    segment.relocations_.push_back(std::move(reloc));

    return ok();
  }

  if (fixup.auth_bind.bind) {
      uint32_t bind_ordinal = ptr_fmt == DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND24 ?
                              fixup.auth_bind24.ordinal :
                              fixup.auth_bind.ordinal;

      if (bind_ordinal >= chained_fixups_->bindings_.size()) {
        LIEF_WARN("Out of range bind ordinal {} (max {})", bind_ordinal, chained_fixups_->bindings_.size());
        return make_error_code(lief_errors::read_error);
      }

      std::unique_ptr<ChainedBindingInfo>& binding = chained_fixups_->bindings_[bind_ordinal];
      binding->offset_          = chain_offset;
      binding->ptr_format_      = ptr_fmt;
      binding->segment_         = &segment;
      /*
       * We use the BindingInfo::address_ to store the imagebase
       * to avoid creating a new attribute in ChainedBindingInfo
       */
      binding->address_         = imagebase;
      ptr_fmt == DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND24 ?
                 binding->set(fixup.auth_bind24) : binding->set(fixup.auth_bind);

      if (Symbol* sym = binding->symbol()) {
        LIEF_DEBUG("{}[  BIND] {}@0x{:x}: {} / sign ext: {:x}",
                   DPREFIX, segment.name(), address, sym->name(), fixup.sign_extended_addend());
        return ok();
      }

      LIEF_DEBUG("{}[  BIND] {}@0x{:x}: <missing symbol> / sign ext: {:x}",
                 DPREFIX, segment.name(), address, fixup.sign_extended_addend());
      LIEF_ERR("Missing symbol for binding at ordinal {}", bind_ordinal);
      return make_error_code(lief_errors::not_found);
  }

  // See comment for: dyld_chained_ptr_generic64
  const uint64_t target = ptr_fmt == DYLD_CHAINED_PTR_FORMAT::PTR_64 ?
                          fixup.unpack_target() + binary_->imagebase() :
                          fixup.unpack_target() + binary_->imagebase();
  auto reloc = std::make_unique<RelocationFixup>(ptr_fmt, imagebase);
  reloc->set(fixup.rebase);
  reloc->architecture_ = binary_->header().cpu_type();
  reloc->segment_      = &segment;
  reloc->size_         = stride_size(ptr_fmt) * BYTE_BITS;
  reloc->offset_       = chain_offset;

  if (Section* section = binary_->section_from_virtual_address(address)) {
    reloc->section_ = section;
  } else {
    LIEF_ERR("Can't find the section associated with the virtual address 0x{:x}", address);
  }

  const auto it_symbol = memoized_symbols_by_address_.find(address);
  if (it_symbol != memoized_symbols_by_address_.end()) {
    reloc->symbol_ = it_symbol->second;
  }

  LIEF_DEBUG("{}[REBASE] {}@0x{:x}: 0x{:x}",
             DPREFIX, segment.name(), address, target);

  segment.relocations_.push_back(std::move(reloc));
  return ok();
}

/* Generic64 Fixup
 * =====================================
 */
ok_error_t BinaryParser::do_chained_fixup(SegmentCommand& segment, uint32_t chain_offset,
                                          const details::dyld_chained_starts_in_segment& seg_info,
                                          const details::dyld_chained_ptr_generic64& fixup)
{
  static constexpr const char DPREFIX[] = "          ";
  const auto ptr_fmt = static_cast<DYLD_CHAINED_PTR_FORMAT>(seg_info.pointer_format);

  const uint64_t address = binary_->imagebase() + chain_offset;
  if (fixup.bind.bind > 0) {
    const uint64_t ordinal = fixup.bind.ordinal;
    if (ordinal >= chained_fixups_->bindings_.size()) {
      LIEF_WARN("Out of range bind ordinal {} (max {})", ordinal, chained_fixups_->bindings_.size());
      return make_error_code(lief_errors::read_error);
    }
    std::unique_ptr<ChainedBindingInfo>& binding = chained_fixups_->bindings_[ordinal];

    binding->offset_          = chain_offset;
    binding->ptr_format_      = ptr_fmt;
    binding->segment_         = &segment;
    /*
     * We use the BindingInfo::address_ to store the imagebase
     * to avoid creating a new attribute in ChainedBindingInfo
     */
    binding->address_ = binary_->imagebase();
    binding->set(fixup.bind);
    if (Symbol* sym = binding->symbol()) {
      LIEF_DEBUG("{}[  BIND] {}@0x{:x}: {} / sign ext: {:x}",
                 DPREFIX, segment.name(), address, sym->name(), fixup.sign_extended_addend());
      return ok();
    }
    LIEF_DEBUG("{}[  BIND] {}@0x{:x}: <missing symbol> / sign ext: {:x}",
               DPREFIX, segment.name(), address, fixup.sign_extended_addend());
    LIEF_ERR("Missing symbol for binding at ordinal {}", ordinal);
    return make_error_code(lief_errors::not_found);
  }


  // The fixup is a rebase.

  /* In the dyld source code (MachOLoaded.cpp) there is
   * a distinction between with DYLD_CHAINED_PTR_64:
   *
   *  // plain rebase (old format target is vmaddr, new format target is offset)
   *  if ( segInfo->pointer_format == DYLD_CHAINED_PTR_64 )
   *      newValue = (void*)(fixupLoc->generic64.unpackedTarget()+slide);
   *  else
   *      newValue = (void*)((uintptr_t)this + fixupLoc->generic64.unpackedTarget());
   *
   * Not sure if it really matters in our case
   */
  const uint64_t target = ptr_fmt == DYLD_CHAINED_PTR_FORMAT::PTR_64 ?
                          fixup.unpack_target() + binary_->imagebase() :
                          fixup.unpack_target() + binary_->imagebase();
  auto reloc = std::make_unique<RelocationFixup>(ptr_fmt, binary_->imagebase());
  reloc->set(fixup.rebase);
  reloc->architecture_ = binary_->header().cpu_type();
  reloc->segment_      = &segment;
  reloc->size_         = stride_size(ptr_fmt) * BYTE_BITS;
  reloc->offset_       = chain_offset;

  if (Section* section = binary_->section_from_virtual_address(address)) {
    reloc->section_ = section;
  } else {
    LIEF_ERR("Can't find the section associated with the virtual address 0x{:x}", address);
  }

  const auto it_symbol = memoized_symbols_by_address_.find(address);
  if (it_symbol != memoized_symbols_by_address_.end()) {
    reloc->symbol_ = it_symbol->second;
  }

  LIEF_DEBUG("{}[REBASE] {}@0x{:x}: 0x{:x}",
             DPREFIX, segment.name(), address, target);

  segment.relocations_.push_back(std::move(reloc));
  return ok();
}


ok_error_t BinaryParser::do_chained_fixup(SegmentCommand& segment, uint32_t chain_offset,
                                          const details::dyld_chained_starts_in_segment& seg_info,
                                          const details::dyld_chained_ptr_generic32& fixup)
{
  static constexpr const char DPREFIX[] = "          ";
  const auto ptr_fmt = static_cast<DYLD_CHAINED_PTR_FORMAT>(seg_info.pointer_format);

  const uint64_t address = binary_->imagebase() + chain_offset;
  if (fixup.bind.bind > 0) {
    const uint64_t ordinal = fixup.bind.ordinal;

    if (ordinal >= chained_fixups_->bindings_.size()) {
      LIEF_WARN("Out of range bind ordinal {} (max {})", ordinal, chained_fixups_->bindings_.size());
      return make_error_code(lief_errors::read_error);
    }

    std::unique_ptr<ChainedBindingInfo>& binding = chained_fixups_->bindings_[ordinal];

    binding->offset_          = chain_offset;
    binding->ptr_format_      = ptr_fmt;
    binding->segment_         = &segment;
    /*
     * We use the BindingInfo::address_ to store the imagebase
     * to avoid creating a new attribute in ChainedBindingInfo
     */
    binding->address_ = binary_->imagebase();
    binding->set(fixup.bind);

    if (Symbol* sym = binding->symbol()) {
      LIEF_DEBUG("{}[  BIND] {}@0x{:x}: {} / sign ext: {:x}",
                 DPREFIX, segment.name(), address, sym->name(), fixup.bind.addend);
      return ok();
    }
    LIEF_DEBUG("{}[  BIND] {}@0x{:x}: <missing symbol> / sign ext: {:x}",
               DPREFIX, segment.name(), address, fixup.bind.addend);
    LIEF_ERR("Missing symbol for binding at ordinal {}", ordinal);
    return make_error_code(lief_errors::not_found);
  }
  // Rebase
  std::unique_ptr<RelocationFixup> reloc;
  if (fixup.rebase.target > seg_info.max_valid_pointer) {
    const uint32_t bias = (0x04000000 + seg_info.max_valid_pointer) / 2;
    const uint64_t target = fixup.rebase.target - bias;

    /* This is used to avoid storing bias information */
    const uint64_t fake_bias   = target - fixup.rebase.target;
    const uint64_t fake_target = target - fake_bias;
    details::dyld_chained_ptr_32_rebase fake_fixup = fixup.rebase;
    fake_fixup.target = fake_target;
    reloc = std::make_unique<RelocationFixup>(ptr_fmt, fake_bias);
    reloc->set(fake_fixup);
  } else {
    reloc = std::make_unique<RelocationFixup>(ptr_fmt, binary_->imagebase());
    reloc->set(fixup.rebase);
  }

  reloc->architecture_ = binary_->header().cpu_type();
  reloc->segment_      = &segment;
  reloc->size_         = stride_size(ptr_fmt) * BYTE_BITS;
  reloc->offset_       = chain_offset;

  if (Section* section = binary_->section_from_virtual_address(address)) {
    reloc->section_ = section;
  } else {
    LIEF_ERR("Can't find the section associated with the virtual address 0x{:x}", address);
  }

  const auto it_symbol = memoized_symbols_by_address_.find(address);
  if (it_symbol != memoized_symbols_by_address_.end()) {
    reloc->symbol_ = it_symbol->second;
  }

  LIEF_DEBUG("{}[REBASE] {}@0x{:x}: 0x{:x}",
             DPREFIX, segment.name(), address, reloc->target());

  segment.relocations_.push_back(std::move(reloc));
  return ok();
}


template<class MACHO_T>
ok_error_t BinaryParser::post_process(SymbolCommand& cmd) {
  LIEF_DEBUG("[^] Post processing LC_SYMTAB");
  using nlist_t = typename MACHO_T::nlist;
  /* n_list table */ {
    SegmentCommand* linkedit = binary_->segment_from_offset(cmd.symbol_offset());
    if (linkedit == nullptr) {
      LIEF_WARN("Can't find the segment that contains the LC_SYMTAB.n_list");
      return make_error_code(lief_errors::not_found);
    };

    span<uint8_t> content = linkedit->writable_content();

    const uint64_t rel_offset = cmd.symbol_offset() - linkedit->file_offset();
    const size_t symtab_size = cmd.numberof_symbols() * sizeof(nlist_t);
    if (rel_offset > content.size() || (rel_offset + symtab_size) > content.size()) {
      LIEF_ERR("The LC_SYMTAB.n_list is out of bounds of the segment '{}'", linkedit->name());
      return make_error_code(lief_errors::read_out_of_bound);
    }

    cmd.symbol_table_ = content.subspan(rel_offset, symtab_size);

    if (LinkEdit::segmentof(*linkedit)) {
      static_cast<LinkEdit*>(linkedit)->symtab_ = &cmd;
    } else {
      LIEF_WARN("Weird: LC_SYMTAB.n_list is not in the __LINKEDIT segment");
    }
  }

  /* strtable */ {
    SegmentCommand* linkedit = binary_->segment_from_offset(cmd.strings_offset());
    if (linkedit == nullptr) {
      LIEF_WARN("Can't find the segment that contains the LC_SYMTAB.n_list");
      return make_error_code(lief_errors::not_found);
    };

    span<uint8_t> content = linkedit->writable_content();

    const uint64_t rel_offset = cmd.strings_offset() - linkedit->file_offset();
    const size_t strtab_size = cmd.strings_size();
    if (rel_offset > content.size() || (rel_offset + strtab_size) > content.size()) {
      LIEF_ERR("The LC_SYMTAB.strtab is out of bounds of the segment {}", linkedit->name());
      return make_error_code(lief_errors::read_out_of_bound);
    }

    cmd.string_table_ = content.subspan(rel_offset, strtab_size);

    if (LinkEdit::segmentof(*linkedit)) {
      static_cast<LinkEdit*>(linkedit)->symtab_ = &cmd;
    } else {
      LIEF_WARN("Weird: LC_SYMTAB.strtab is not in the __LINKEDIT segment");
    }
  }

  cmd.original_nb_symbols_ = cmd.numberof_symbols();
  cmd.original_str_size_   = cmd.strings_size();
  return ok();
}


template<class MACHO_T>
ok_error_t BinaryParser::post_process(FunctionStarts& cmd) {
  LIEF_DEBUG("[^] Post processing LC_FUNCTION_STARTS");
  SegmentCommand* linkedit = binary_->segment_from_offset(cmd.data_offset());
  if (linkedit == nullptr) {
    LIEF_WARN("Can't find the segment that contains the LC_FUNCTION_STARTS");
    return make_error_code(lief_errors::not_found);
  };

  span<uint8_t> content = linkedit->writable_content();

  const uint64_t rel_offset = cmd.data_offset() - linkedit->file_offset();
  if (rel_offset > content.size() || (rel_offset + cmd.data_size()) > content.size()) {
    LIEF_ERR("The LC_FUNCTION_STARTS is out of bounds of the segment '{}'", linkedit->name());
    return make_error_code(lief_errors::read_out_of_bound);
  }

  cmd.content_ = content.subspan(rel_offset, cmd.data_size());

  if (LinkEdit::segmentof(*linkedit)) {
    static_cast<LinkEdit*>(linkedit)->fstarts_ = &cmd;
  } else {
    LIEF_WARN("Weird: LC_FUNCTION_STARTS is not in the __LINKEDIT segment");
  }
  return ok();
}


template<class MACHO_T>
ok_error_t BinaryParser::post_process(DataInCode& cmd) {
  LIEF_DEBUG("[^] Post processing LC_DATA_IN_CODE");
  SegmentCommand* linkedit = binary_->segment_from_offset(cmd.data_offset());
  if (linkedit == nullptr) {
    LIEF_WARN("Can't find the segment that contains the LC_DATA_IN_CODE");
    return make_error_code(lief_errors::not_found);
  };

  span<uint8_t> content = linkedit->writable_content();

  const uint64_t rel_offset = cmd.data_offset() - linkedit->file_offset();
  if (rel_offset > content.size() || (rel_offset + cmd.data_size()) > content.size()) {
    LIEF_ERR("The LC_DATA_IN_CODE is out of bounds of the segment '{}'", linkedit->name());
    return make_error_code(lief_errors::read_out_of_bound);
  }

  cmd.content_ = content.subspan(rel_offset, cmd.data_size());

  if (LinkEdit::segmentof(*linkedit)) {
    static_cast<LinkEdit*>(linkedit)->data_code_ = &cmd;
  } else {
    LIEF_WARN("Weird: LC_DATA_IN_CODE is not in the __LINKEDIT segment");
  }
  return ok();
}

template<class MACHO_T>
ok_error_t BinaryParser::post_process(SegmentSplitInfo& cmd) {
  LIEF_DEBUG("[^] Post processing LC_SEGMENT_SPLIT_INFO");
  SegmentCommand* linkedit = binary_->segment_from_offset(cmd.data_offset());
  if (linkedit == nullptr) {
    LIEF_WARN("Can't find the segment that contains the LC_SEGMENT_SPLIT_INFO");
    return make_error_code(lief_errors::not_found);
  };

  span<uint8_t> content = linkedit->writable_content();

  const uint64_t rel_offset = cmd.data_offset() - linkedit->file_offset();
  if (rel_offset > content.size() || (rel_offset + cmd.data_size()) > content.size()) {
    LIEF_ERR("The LC_SEGMENT_SPLIT_INFO is out of bounds of the segment '{}'", linkedit->name());
    return make_error_code(lief_errors::read_out_of_bound);
  }

  cmd.content_ = content.subspan(rel_offset, cmd.data_size());

  if (LinkEdit::segmentof(*linkedit)) {
    static_cast<LinkEdit*>(linkedit)->seg_split_ = &cmd;
  } else {
    LIEF_WARN("Weird: LC_SEGMENT_SPLIT_INFO is not in the __LINKEDIT segment");
  }
  return ok();
}


template<class MACHO_T>
ok_error_t BinaryParser::post_process(DynamicSymbolCommand& cmd) {
  LIEF_DEBUG("[^] Post processing LC_DYSYMTAB");
  std::vector<Symbol*> symtab;
  symtab.reserve(binary_->symbols_.size());
  size_t isym = 0;
  for (const std::unique_ptr<Symbol>& sym : binary_->symbols_) {
    if (sym->origin() != SYMBOL_ORIGINS::SYM_ORIGIN_LC_SYMTAB) {
      continue;
    }

    if (cmd.nb_local_symbols() > 0 &&
        cmd.idx_local_symbol() <= isym  && isym < (cmd.idx_local_symbol() + cmd.nb_local_symbols()))
    {
      sym->category_ = Symbol::CATEGORY::LOCAL;
    }

    if (cmd.nb_external_define_symbols() > 0 &&
        cmd.idx_external_define_symbol() <= isym  && isym < (cmd.idx_external_define_symbol() + cmd.nb_external_define_symbols()))
    {
      sym->category_ = Symbol::CATEGORY::EXTERNAL;
    }

    if (cmd.nb_undefined_symbols() > 0 &&
        cmd.idx_undefined_symbol() <= isym  && isym < (cmd.idx_undefined_symbol() + cmd.nb_undefined_symbols()))
    {
      sym->category_ = Symbol::CATEGORY::UNDEFINED;
    }
    symtab.push_back(sym.get());
    ++isym;
  }

  stream_->setpos(cmd.indirect_symbol_offset());
  for (size_t i = 0; i < cmd.nb_indirect_symbols(); ++i) {
    uint32_t index = 0;
    if (auto res = stream_->read<uint32_t>()) {
      index = *res;
    } else {
      LIEF_ERR("Can't read indirect symbol #{}", index);
      break;
    }

    if (index == details::INDIRECT_SYMBOL_ABS) {
      cmd.indirect_symbols_.push_back(const_cast<Symbol*>(&Symbol::indirect_abs()));
      continue;
    }
    if (index == details::INDIRECT_SYMBOL_LOCAL) {
      cmd.indirect_symbols_.push_back(const_cast<Symbol*>(&Symbol::indirect_local()));
      continue;
    }

    if (index >= symtab.size()) {
      LIEF_ERR("Indirect symbol index is out of range ({} vs max sym: {})",
               index, symtab.size());
      break;
    }

    Symbol* indirect = symtab[index];
    LIEF_DEBUG("  indirectsyms[{}] = {}", index, indirect->name());
    cmd.indirect_symbols_.push_back(indirect);
  }
  LIEF_DEBUG("indirect_symbols_.size(): {} (nb_indirect_symbols: {})",
             cmd.indirect_symbols_.size(), cmd.nb_indirect_symbols());
  return ok();
}

template<class MACHO_T>
ok_error_t BinaryParser::post_process(LinkerOptHint& cmd) {
  LIEF_DEBUG("[^] Post processing LC_LINKER_OPTIMIZATION_HINT");
  SegmentCommand* linkedit = binary_->segment_from_offset(cmd.data_offset());
  if (linkedit == nullptr) {
    LIEF_WARN("Can't find the segment that contains the LC_LINKER_OPTIMIZATION_HINT");
    return make_error_code(lief_errors::not_found);
  };

  span<uint8_t> content = linkedit->writable_content();

  const uint64_t rel_offset = cmd.data_offset() - linkedit->file_offset();
  if (rel_offset > content.size() || (rel_offset + cmd.data_size()) > content.size()) {
    LIEF_ERR("The LC_LINKER_OPTIMIZATION_HINT is out of bounds of the segment '{}'", linkedit->name());
    return make_error_code(lief_errors::read_out_of_bound);
  }

  cmd.content_ = content.subspan(rel_offset, cmd.data_size());

  if (LinkEdit::segmentof(*linkedit)) {
    static_cast<LinkEdit*>(linkedit)->linker_opt_ = &cmd;
  } else {
    LIEF_WARN("Weird: LC_LINKER_OPTIMIZATION_HINT is not in the __LINKEDIT segment");
  }
  return ok();
}

template<class MACHO_T>
ok_error_t BinaryParser::post_process(CodeSignature& cmd) {
  LIEF_DEBUG("[^] Post processing LC_CODE_SIGNATURE");
  SegmentCommand* linkedit = binary_->segment_from_offset(cmd.data_offset());
  if (linkedit == nullptr) {
    LIEF_WARN("Can't find the segment that contains the LC_CODE_SIGNATURE");
    return make_error_code(lief_errors::not_found);
  };

  span<uint8_t> content = linkedit->writable_content();

  const uint64_t rel_offset = cmd.data_offset() - linkedit->file_offset();
  if (rel_offset > content.size() || (rel_offset + cmd.data_size()) > content.size()) {
    LIEF_ERR("The LC_CODE_SIGNATURE is out of bounds of the segment '{}'", linkedit->name());
    return make_error_code(lief_errors::read_out_of_bound);
  }

  cmd.content_ = content.subspan(rel_offset, cmd.data_size());

  if (LinkEdit::segmentof(*linkedit)) {
    static_cast<LinkEdit*>(linkedit)->code_sig_ = &cmd;
  } else {
    LIEF_WARN("Weird: LC_CODE_SIGNATURE is not in the __LINKEDIT segment");
  }
  return ok();
}

template<class MACHO_T>
ok_error_t BinaryParser::post_process(CodeSignatureDir& cmd) {
  LIEF_DEBUG("[^] Post processing LC_DYLIB_CODE_SIGN_DRS");
  SegmentCommand* linkedit = binary_->segment_from_offset(cmd.data_offset());
  if (linkedit == nullptr) {
    LIEF_WARN("Can't find the segment that contains the LC_DYLIB_CODE_SIGN_DRS");
    return make_error_code(lief_errors::not_found);
  };

  span<uint8_t> content = linkedit->writable_content();

  const uint64_t rel_offset = cmd.data_offset() - linkedit->file_offset();
  if (rel_offset > content.size() || (rel_offset + cmd.data_size()) > content.size()) {
    LIEF_ERR("The LC_DYLIB_CODE_SIGN_DRS is out of bounds of the segment '{}'", linkedit->name());
    return make_error_code(lief_errors::read_out_of_bound);
  }

  cmd.content_ = content.subspan(rel_offset, cmd.data_size());

  if (LinkEdit::segmentof(*linkedit)) {
    static_cast<LinkEdit*>(linkedit)->code_sig_dir_ = &cmd;
  } else {
    LIEF_WARN("Weird: LC_DYLIB_CODE_SIGN_DRS is not in the __LINKEDIT segment");
  }
  return ok();
}


template<class MACHO_T>
ok_error_t BinaryParser::post_process(TwoLevelHints& cmd) {
  LIEF_DEBUG("[^] Post processing LC_DYLIB_CODE_SIGN_DRS");
  SegmentCommand* linkedit = binary_->segment_from_offset(cmd.offset());
  if (linkedit == nullptr) {
    LIEF_WARN("Can't find the segment that contains the LC_TWOLEVEL_HINTS");
    return make_error_code(lief_errors::not_found);
  };

  const size_t raw_size = cmd.original_nb_hints() * sizeof(uint32_t);
  span<uint8_t> content = linkedit->writable_content();

  const uint64_t rel_offset = cmd.offset() - linkedit->file_offset();
  if (rel_offset > content.size() || (rel_offset + raw_size) > content.size()) {
    LIEF_ERR("The LC_TWOLEVEL_HINTS is out of bounds of the segment '{}'", linkedit->name());
    return make_error_code(lief_errors::read_out_of_bound);
  }

  cmd.content_ = content.subspan(rel_offset, raw_size);

  if (LinkEdit::segmentof(*linkedit)) {
    static_cast<LinkEdit*>(linkedit)->two_lvl_hint_ = &cmd;
  } else {
    LIEF_WARN("Weird: LC_TWOLEVEL_HINTS is not in the __LINKEDIT segment");
  }
  return ok();
}






}
}
