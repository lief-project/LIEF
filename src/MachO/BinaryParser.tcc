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

#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/BinaryParser.hpp"
#include "LIEF/MachO/Section.hpp"
#include "LIEF/MachO/DyldInfo.hpp"
#include "LIEF/MachO/FunctionStarts.hpp"
#include "LIEF/MachO/SourceVersion.hpp"
#include "LIEF/MachO/VersionMin.hpp"
#include "LIEF/MachO/Relocation.hpp"
#include "LIEF/MachO/RelocationObject.hpp"
#include "LIEF/MachO/RelocationDyld.hpp"
#include "LIEF/MachO/SubFramework.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"
#include "LIEF/MachO/DylibCommand.hpp"
#include "LIEF/MachO/RPathCommand.hpp"
#include "LIEF/MachO/UUIDCommand.hpp"
#include "LIEF/MachO/DylinkerCommand.hpp"
#include "LIEF/MachO/ThreadCommand.hpp"
#include "LIEF/MachO/SymbolCommand.hpp"
#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/DynamicSymbolCommand.hpp"
#include "LIEF/MachO/EnumToString.hpp"
#include "LIEF/MachO/CodeSignature.hpp"
#include "LIEF/MachO/DataInCode.hpp"
#include "LIEF/MachO/MainCommand.hpp"
#include "LIEF/MachO/SegmentSplitInfo.hpp"
#include "LIEF/MachO/DyldEnvironment.hpp"
#include "LIEF/MachO/EncryptionInfo.hpp"
#include "LIEF/MachO/BindingInfo.hpp"
#include "LIEF/MachO/FilesetCommand.hpp"
#include "MachO/Structures.hpp"

#include "Object.tcc"


namespace LIEF {
namespace MachO {

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

  for (Section& section : binary_->sections()) {
    try {
      parse_relocations<MACHO_T>(section);
    } catch (const exception& e) {
      LIEF_WARN("{}", e.what());
    }
  }

  if (binary_->has_dyld_info()) {

    if (config_.parse_dyld_exports) {
      try {
        parse_dyldinfo_export();
      } catch (const exception& e) {
        LIEF_WARN("{}", e.what());
      }
    }

    if (config_.parse_dyld_bindings) {
      try {
        parse_dyldinfo_binds<MACHO_T>();
      } catch (const exception& e) {
        LIEF_WARN("{}", e.what());
      }
    }

    if (config_.parse_dyld_rebases) {
      try {
        parse_dyldinfo_rebases<MACHO_T>();
      } catch (const exception& e) {
        LIEF_WARN("{}", e.what());
      }
    }

    if (DyldInfo* dyld = binary_->dyld_info()) {
      // Backtrack the Dyld info object in the segment to keep span consistent
      for (SegmentCommand* segment : binary_->segments_) {
        segment->dyld_ = dyld;
      }
    }
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
          load_command = std::make_unique<SegmentCommand>(*segment_cmd);

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
            if (str_idx > 0) {
              if (auto name = stream_->peek_string_at(cmd->stroff + str_idx)) {
                symbol->name(*name);
                memoized_symbols_[*name] = symbol.get();
              } else {
                LIEF_WARN("Can't read symbol's name for nlist #{}", i);
              }
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
      case LOAD_COMMAND_TYPES::LC_CODE_SIGNATURE:
        {
          /*
           * DO NOT FORGET TO UPDATE CodeSignature::classof
           */
          const auto cmd = stream_->peek<details::linkedit_data_command>(loadcommands_offset);
          if (!cmd) {
            LIEF_ERR("Can't parse linkedit_data_command for LC_CODE_SIGNATURE/LC_DYLIB_CODE_SIGN_DRS");
            break;
          }
          load_command = std::make_unique<CodeSignature>(*cmd);
          auto* sig = load_command->as<CodeSignature>();
          if (!stream_->peek_data(sig->raw_signature_, sig->data_offset(), sig->data_size())) {
            LIEF_ERR("Can't read the content of the signature command");
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

            LIEF_DEBUG("Value: 0x{:x}", value);
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


          try {
            /* TODO(romain): This part needs to be refactored
             * we should not have to make this kind construction and move
             * with the BinaryParser constructor
             */
            const size_t current_pos = stream_->pos();
            stream_->setpos(cmd->fileoff);
            BinaryParser bp;
            bp.stream_ = std::move(stream_);
            bp.config_ = config_;
            if (!bp.init_and_parse()) {
              LIEF_WARN("Parsing the Binary fileset raised error.");
            }

            stream_ = std::move(bp.stream_);
            stream_->setpos(current_pos);

            if (bp.binary_ != nullptr) {
              std::unique_ptr<Binary> filset_bin = std::move(bp.binary_);
              filset_bin->name_ = *entry_name;
              binary_->filesets_.push_back(std::move(filset_bin));
            }

          } catch (const std::exception& e) {
            LIEF_DEBUG("{}", e.what());
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

  try {
    parse_dyldinfo_generic_bind<MACHO_T>();
  } catch (const exception& e) {
    LIEF_ERR("Can't correctly parse Dyld binding info");
    return make_error_code(lief_errors::corrupted);
  }


  try {
    parse_dyldinfo_weak_bind<MACHO_T>();
  } catch (const exception& e) {
    LIEF_ERR("Can't correctly parse weak Dyld binding info");
    return make_error_code(lief_errors::corrupted);
  }


  try {
    parse_dyldinfo_lazy_bind<MACHO_T>();
  } catch (const exception& e) {
    LIEF_ERR("Can't correctly parse lazy Dyld binding info");
    return make_error_code(lief_errors::corrupted);
  }
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
                auto val = stream_->read_uleb128();
                if (!val) {
                  LIEF_ERR("Can't read BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB count");
                  break;
                }
                count = *val;
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
  auto binding_info = std::make_unique<BindingInfo>(
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
  static constexpr uint8_t BYTE_BIT = std::numeric_limits<uint8_t>::digits;
  static_assert(BYTE_BIT == 8, "The number of bits in a byte is not 8");

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
    LIEF_ERR("Can't find the section associated with the virtual address 0x{:x}");
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
        reloc->size_ = sizeof(pint_t) * BYTE_BIT;
        break;
      }


    case REBASE_TYPES::REBASE_TYPE_TEXT_ABSOLUTE32:
    case REBASE_TYPES::REBASE_TYPE_TEXT_PCREL32:
      {
        reloc->size_ = sizeof(uint32_t) * BYTE_BIT;
        break;
      }

    case REBASE_TYPES::REBASE_TYPE_THREADED:
      {
        reloc->size_ = sizeof(pint_t) * BYTE_BIT;
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




}
}
