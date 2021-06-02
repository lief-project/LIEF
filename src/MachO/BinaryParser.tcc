/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
void BinaryParser::parse(void) {
  this->parse_header<MACHO_T>();
  if (this->binary_->header().nb_cmds() > 0) {
    this->parse_load_commands<MACHO_T>();
  }

  for (Section& section : this->binary_->sections()) {
    try {
      this->parse_relocations<MACHO_T>(section);
    } catch (const exception& e) {
      LIEF_WARN("{}", e.what());
    }
  }

  if (this->binary_->has_dyld_info() and this->config_.parse_dyldinfo_deeply()) {

    try {
      this->parse_dyldinfo_binds<MACHO_T>();
    } catch (const exception& e) {
      LIEF_WARN("{}", e.what());
    }

    try {
      this->parse_dyldinfo_export();
    } catch (const exception& e) {
      LIEF_WARN("{}", e.what());
    }

    try {
      this->parse_dyldinfo_rebases<MACHO_T>();
    } catch (const exception& e) {
      LIEF_WARN("{}", e.what());
    }

  }
}

template<class MACHO_T>
void BinaryParser::parse_header(void) {
  using header_t = typename MACHO_T::header;
  this->binary_->header_ = &this->stream_->peek<header_t>(0);
}


template<class MACHO_T>
void BinaryParser::parse_load_commands(void) {
  using header_t          = typename MACHO_T::header;
  using segment_command_t = typename MACHO_T::segment_command;
  using section_t         = typename MACHO_T::section;

  LIEF_DEBUG("[+] Building Load commands");

  const Header& header = this->binary_->header();
  uint64_t loadcommands_offset = sizeof(header_t);

  if ((loadcommands_offset + header.sizeof_cmds()) > this->stream_->size()) {
    throw corrupted("Commands are corrupted");
  }

  size_t nbcmds = header.nb_cmds();

  if (header.nb_cmds() > BinaryParser::MAX_COMMANDS) {
    nbcmds = BinaryParser::MAX_COMMANDS;
    LIEF_WARN("Only the first #{:d} will be parsed", nbcmds);
  }

  uint32_t low_fileoff = -1U;
  for (size_t i = 0; i < nbcmds; ++i) {
    if (not this->stream_->can_read<load_command>(loadcommands_offset)) {
      break;
    }
    const load_command& command = this->stream_->peek<load_command>(loadcommands_offset);

    std::unique_ptr<LoadCommand> load_command{nullptr};
    switch (static_cast<LOAD_COMMAND_TYPES>(command.cmd)) {

      // ===============
      // Segment command
      // ===============
      case LOAD_COMMAND_TYPES::LC_SEGMENT_64:
      case LOAD_COMMAND_TYPES::LC_SEGMENT:
        {
          uint64_t local_offset = loadcommands_offset;
          load_command = std::unique_ptr<SegmentCommand>{new SegmentCommand{&this->stream_->peek<segment_command_t>(loadcommands_offset)}};

          local_offset += sizeof(segment_command_t);

          SegmentCommand* segment = reinterpret_cast<SegmentCommand*>(load_command.get());
          segment->index_ = this->binary_->segments_.size();
          this->binary_->offset_seg_[segment->file_offset()] = segment;
          this->binary_->segments_.push_back(segment);

          const uint8_t* content = this->stream_->peek_array<uint8_t>(segment->file_offset(), segment->file_size(), /* check */ false);
          if (content != nullptr) {
            segment->content({
                content,
                content + segment->file_size()
                });
          } else {
            LIEF_ERR("Segment content corrupted!");
          }

          // --------
          // Sections
          // --------
          for (size_t j = 0; j < segment->numberof_sections(); ++j) {
            const section_t* section_header = &this->stream_->peek<section_t>(local_offset);
            std::unique_ptr<Section> section{new Section{section_header}};
            this->binary_->sections_.push_back(section.get());
            if (section->size_ > 0 and
              section->type() != MACHO_SECTION_TYPES::S_ZEROFILL and
              section->type() != MACHO_SECTION_TYPES::S_THREAD_LOCAL_ZEROFILL and
              section->offset_ < low_fileoff) {
              low_fileoff = section->offset_;
            }
            section->segment_ = segment;
            segment->sections_.push_back(section.release());
            local_offset += sizeof(section_t);
          }
          if (segment->numberof_sections() == 0 and
              segment->file_offset() != 0 and
              segment->file_size() != 0 and
              segment->file_offset() < low_fileoff) {
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
          const dylib_command* cmd = &this->stream_->peek<dylib_command>(loadcommands_offset);

          load_command = std::unique_ptr<DylibCommand>{new DylibCommand{cmd}};
          const uint32_t str_name_offset = cmd->dylib.name;
          std::string name = this->stream_->peek_string_at(loadcommands_offset + str_name_offset);

          auto* lib = reinterpret_cast<DylibCommand*>(load_command.get());
          lib->name(std::move(name));
          this->binary_->libraries_.push_back(lib);
          break;
        }

      // =============
      // RPath Command
      // =============
      case LOAD_COMMAND_TYPES::LC_RPATH:
        {
          const rpath_command* cmd = &this->stream_->peek<rpath_command>(loadcommands_offset);

          load_command = std::unique_ptr<RPathCommand>{new RPathCommand{cmd}};
          const uint32_t str_path_offset = cmd->path;
          std::string path = this->stream_->peek_string_at(loadcommands_offset + str_path_offset);

          reinterpret_cast<RPathCommand*>(load_command.get())->path(path);
          break;
        }

      // ====
      // UUID
      // ====
      case LOAD_COMMAND_TYPES::LC_UUID:
        {
          LIEF_DEBUG("[+] Building UUID");
          const uuid_command* cmd = &this->stream_->peek<uuid_command>(loadcommands_offset);
          load_command = std::unique_ptr<UUIDCommand>{new UUIDCommand{cmd}};
          break;
        }

      // ==============
      // Dynamic Linker
      // ==============
      case LOAD_COMMAND_TYPES::LC_LOAD_DYLINKER:
      case LOAD_COMMAND_TYPES::LC_ID_DYLINKER:
        {
          const dylinker_command* cmd = &this->stream_->peek<dylinker_command>(loadcommands_offset);

          const uint32_t linker_name_offset = cmd->name;
          std::string name = this->stream_->peek_string_at(
             loadcommands_offset +
             linker_name_offset);

          load_command = std::unique_ptr<DylinkerCommand>{new DylinkerCommand{cmd}};
          reinterpret_cast<DylinkerCommand*>(load_command.get())->name(name);
          break;
        }

      // ==============
      // Prebound Dylib
      // ==============
      //case LOAD_COMMAND_TYPES::LC_PREBOUND_DYLIB:
      //  {
      //    LIEF_DEBUG("[+] Parsing LC_PREBOUND_DYLIB");

      //    load_command = std::unique_ptr<LoadCommand>{new LoadCommand{&command}};
      //    const prebound_dylib_command* cmd = &this->stream_->peek<prebound_dylib_command>(loadcommands_offset);


      //    std::string name = this->stream_->peek_string_at(
      //       loadcommands_offset +
      //       cmd->name);

      //    //uint32_t sizeof_linked_modules = (cmd->nmodules / 8) + (cmd->nmodules % 8);

      //    break;
      //  }

      // ======
      // Thread
      // ======
      case LOAD_COMMAND_TYPES::LC_THREAD:
      case LOAD_COMMAND_TYPES::LC_UNIXTHREAD:
        {
          LIEF_DEBUG("[+] Parsing LC_THREAD");

          const thread_command* cmd = &this->stream_->peek<thread_command>(loadcommands_offset);
          load_command = std::unique_ptr<ThreadCommand>{new ThreadCommand{cmd}};

          ThreadCommand* thread = reinterpret_cast<ThreadCommand*>(load_command.get());
          thread->architecture_ = this->binary_->header().cpu_type();
          LIEF_DEBUG("FLAVOR: {} | COUNT: {}", cmd->flavor, cmd->count);
          switch(this->binary_->header().cpu_type()) {
            case CPU_TYPES::CPU_TYPE_X86:
              {
                const uint8_t* pstart = this->stream_->peek_array<uint8_t>(loadcommands_offset + sizeof(thread_command), sizeof(x86_thread_state_t), /* check */ false);
                if (pstart != nullptr) {
                  thread->state_ = {pstart, pstart + sizeof(x86_thread_state_t)};
                }

                break;
              }

            case CPU_TYPES::CPU_TYPE_X86_64:
              {
                const uint8_t* pstart = this->stream_->peek_array<uint8_t>(loadcommands_offset + sizeof(thread_command), sizeof(x86_thread_state64_t), /* check */ false);

                if (pstart != nullptr) {
                  thread->state_ = {pstart, pstart + sizeof(x86_thread_state64_t)};
                }
                break;
              }

            case CPU_TYPES::CPU_TYPE_ARM:
              {
                const uint8_t* pstart = this->stream_->peek_array<uint8_t>(loadcommands_offset + sizeof(thread_command), sizeof(arm_thread_state_t), /* check */ false);

                if (pstart != nullptr) {
                  thread->state_ = {pstart, pstart + sizeof(arm_thread_state_t)};
                }
                break;
              }

            case CPU_TYPES::CPU_TYPE_ARM64:
              {
                const uint8_t* pstart = this->stream_->peek_array<uint8_t>(loadcommands_offset + sizeof(thread_command), sizeof(arm_thread_state64_t), /* check */ false);

                if (pstart != nullptr) {
                  thread->state_ = {pstart, pstart + sizeof(arm_thread_state64_t)};
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
          using nlist_t = typename MACHO_T::nlist;
          LIEF_DEBUG("[+] Parsing symbols");

          const symtab_command* cmd = &this->stream_->peek<symtab_command>(loadcommands_offset);


          load_command = std::unique_ptr<SymbolCommand>{new SymbolCommand{cmd}};


          const nlist_t* nlist = this->stream_->peek_array<nlist_t>(cmd->symoff, cmd->nsyms, /* check */ false);
          if (nlist == nullptr) {
            LIEF_ERR("Symbols corrupted!");
            break;
          }

          for (size_t j = 0; j < cmd->nsyms; ++j) {
            std::unique_ptr<Symbol> symbol{new Symbol{&nlist[j]}};
            uint32_t idx = nlist[j].n_strx;
            if (idx > 0) {
              symbol->name(
                  this->stream_->peek_string_at(cmd->stroff + idx));
            }
            Symbol* symbol_ptr = symbol.release();
            this->binary_->symbols_.push_back(symbol_ptr);
            this->memoized_symbols_[symbol_ptr->name()] = symbol_ptr;
            this->memoized_symbols_by_address_[symbol_ptr->value()] = symbol_ptr;
          }

          break;
        }

      // ===============
      // Dynamic Symbols
      // ===============
      case LOAD_COMMAND_TYPES::LC_DYSYMTAB:
        {
          LIEF_DEBUG("[+] Parsing dynamic symbols");
          const dysymtab_command* cmd = &this->stream_->peek<dysymtab_command>(loadcommands_offset);

          load_command = std::unique_ptr<DynamicSymbolCommand>{new DynamicSymbolCommand{cmd}};
          break;
        }

      // ===============
      // Dyd Info
      // ===============
      case LOAD_COMMAND_TYPES::LC_DYLD_INFO:
      case LOAD_COMMAND_TYPES::LC_DYLD_INFO_ONLY:
        {
          LIEF_DEBUG("[+] Parsing dyld information");
          const dyld_info_command* cmd = &this->stream_->peek<dyld_info_command>(loadcommands_offset);

          load_command = std::unique_ptr<DyldInfo>{new DyldInfo{cmd}};
          reinterpret_cast<DyldInfo*>(load_command.get())->binary_ = this->binary_;
          break;
        }

      // ===============
      // Source Version
      // ===============
      case LOAD_COMMAND_TYPES::LC_SOURCE_VERSION:
        {
          LIEF_DEBUG("[+] Parsing LC_SOURCE_VERSION");

          const source_version_command* cmd = &this->stream_->peek<source_version_command>(loadcommands_offset);

          load_command = std::unique_ptr<SourceVersion>{new SourceVersion{cmd}};
          LIEF_DEBUG("Version: 0x{:x}", cmd->version);
          break;
        }

      case LOAD_COMMAND_TYPES::LC_VERSION_MIN_MACOSX:
      case LOAD_COMMAND_TYPES::LC_VERSION_MIN_IPHONEOS:
        {
          LIEF_DEBUG("[+] Parsing {}", to_string(static_cast<LOAD_COMMAND_TYPES>(command.cmd)));

          const version_min_command* cmd = &this->stream_->peek<version_min_command>(loadcommands_offset);
          LIEF_DEBUG("Version: 0x{:x} | SDK: 0x{:x}", cmd->version, cmd->sdk);

          load_command = std::unique_ptr<VersionMin>{new VersionMin{cmd}};
          break;
        }


      case LOAD_COMMAND_TYPES::LC_BUILD_VERSION:
        {
          LIEF_DEBUG("[+] Parsing {}", to_string(static_cast<LOAD_COMMAND_TYPES>(command.cmd)));

          const auto cmd = &this->stream_->peek<build_version_command>(loadcommands_offset);

          load_command = std::unique_ptr<BuildVersion>{new BuildVersion{cmd}};
          BuildVersion* build_version = load_command->as<BuildVersion>();
          for (size_t i = 0; i < cmd->ntools; ++i) {
            const uint64_t cmd_offset = loadcommands_offset + sizeof(build_version_command) + i * sizeof(build_tool_version);
            if (not this->stream_->can_read<build_tool_version>(cmd_offset)) {
              break;
            }

            auto&& tool_struct = this->stream_->peek<build_tool_version>(cmd_offset);
            build_version->tools_.emplace_back(tool_struct);
          }
          break;
        }

      // =================
      // Code Signature
      // =================
      case LOAD_COMMAND_TYPES::LC_DYLIB_CODE_SIGN_DRS:
      case LOAD_COMMAND_TYPES::LC_CODE_SIGNATURE:
        {

          const linkedit_data_command* cmd = &this->stream_->peek<linkedit_data_command>(loadcommands_offset);
          load_command = std::unique_ptr<CodeSignature>{new CodeSignature{cmd}};
          CodeSignature* sig = load_command.get()->as<CodeSignature>();

          const uint8_t* content = this->stream_->peek_array<uint8_t>(sig->data_offset(), sig->data_size(), /* check */ false);
          if (content != nullptr) {
            sig->raw_signature_ = {content, content + sig->data_size()};
          }

          break;
        }

      // ==============
      // Data in Code
      // ==============
      case LOAD_COMMAND_TYPES::LC_DATA_IN_CODE:
        {

          const linkedit_data_command* cmd = &this->stream_->peek<linkedit_data_command>(loadcommands_offset);
          load_command = std::unique_ptr<DataInCode>{new DataInCode{cmd}};
          DataInCode* datacode = load_command.get()->as<DataInCode>();

          const size_t nb_entries = datacode->data_size() / sizeof(data_in_code_entry);
          const data_in_code_entry* entries = this->stream_->peek_array<data_in_code_entry>(datacode->data_offset(), nb_entries, /* check */ false);
          if (entries != nullptr) {
            for (size_t i = 0; i < nb_entries; ++i) {
              datacode->add(&entries[i]);
            }
          }
          break;
        }


      // =======
      // LC_MAIN
      // =======
      case LOAD_COMMAND_TYPES::LC_MAIN:
        {
          LIEF_DEBUG("[+] Parsing LC_MAIN");

          const entry_point_command* cmd = &this->stream_->peek<entry_point_command>(loadcommands_offset);

          load_command = std::unique_ptr<MainCommand>{new MainCommand{cmd}};
          break;
        }

      // ==================
      // LC_FUNCTION_STARTS
      // ==================
      case LOAD_COMMAND_TYPES::LC_FUNCTION_STARTS:
        {
          LIEF_DEBUG("[+] Parsing LC_FUNCTION_STARTS");
          const linkedit_data_command* cmd = &this->stream_->peek<linkedit_data_command>(loadcommands_offset);
          load_command = std::unique_ptr<FunctionStarts>{new FunctionStarts{cmd}};

          uint64_t value = 0;
          FunctionStarts* fstart = reinterpret_cast<FunctionStarts*>(load_command.get());
          this->stream_->setpos(cmd->dataoff);

          do {
            uint64_t val = this->stream_->read_uleb128();
            if (val == 0) {
              break;
            }
            value += val;

            LIEF_DEBUG("Value: 0x{:x}", value);
            fstart->add_function(value);
          } while(this->stream_->pos() < (cmd->dataoff + cmd->datasize));

          break;
        }
      case LOAD_COMMAND_TYPES::LC_SEGMENT_SPLIT_INFO:
        {
          //static constexpr uint8_t DYLD_CACHE_ADJ_V2_FORMAT = 0x7F;
          LIEF_DEBUG("[+] Parsing LC_SEGMENT_SPLIT_INFO");
          const linkedit_data_command& cmd = this->stream_->peek<linkedit_data_command>(loadcommands_offset);
          load_command = std::unique_ptr<SegmentSplitInfo>{new SegmentSplitInfo{&cmd}};
          //const uint32_t start = cmd->dataoff;
          //const uint32_t size  = cmd->datasize;

          //load_command = std::unique_ptr<LoadCommand>{new LoadCommand{&command}};

          //const size_t saved_pos = this->stream_->pos();
          //this->stream_->setpos(start);

          //// 1. Type
          //uint8_t kind = this->stream_->peek<uint8_t>();
          //if (kind == DYLD_CACHE_ADJ_V2_FORMAT) {
          //  std::cout  << "V2 Format" << std::endl;
          //} else {
          //  std::cout  << "V1 Format" << std::endl;
          //  while (this->stream_->pos() < (start + size)) {
          //    uint8_t kind = this->stream_->read<uint8_t>();
          //    uint64_t cache_offset = 0;
          //    while (uint64_t delta = this->stream_->read_uleb128()) {
          //      cache_offset += delta;
          //    }
          //  }
          //}
          //this->stream_->setpos(saved_pos);
          break;

        }

      case LOAD_COMMAND_TYPES::LC_SUB_FRAMEWORK:
        {
          const sub_framework_command& cmd = this->stream_->peek<sub_framework_command>(loadcommands_offset);
          std::string u = this->stream_->peek_string_at(loadcommands_offset + cmd.umbrella);
          std::unique_ptr<SubFramework> sf{new SubFramework{&cmd}};
          sf->umbrella(u);
          load_command = std::move(sf);
          break;
        }


      case LOAD_COMMAND_TYPES::LC_DYLD_ENVIRONMENT:
        {
          const dylinker_command& cmd = this->stream_->peek<dylinker_command>(loadcommands_offset);

          std::string value = this->stream_->peek_string_at(loadcommands_offset + cmd.name);
          std::unique_ptr<DyldEnvironment> env{new DyldEnvironment{&cmd}};
          env->value(value);
          load_command = std::move(env);
          break;
        }


      // ================
      // Encryption Info
      // ================
      case LOAD_COMMAND_TYPES::LC_ENCRYPTION_INFO:
      case LOAD_COMMAND_TYPES::LC_ENCRYPTION_INFO_64:
        {
          LIEF_DEBUG("[+] Parsing {}", to_string(static_cast<LOAD_COMMAND_TYPES>(command.cmd)));
          const encryption_info_command* cmd = &this->stream_->peek<encryption_info_command>(loadcommands_offset);
          load_command = std::unique_ptr<EncryptionInfo>{new EncryptionInfo{cmd}};
          break;
        }


      default:
        {
          LIEF_WARN("Command '{}' not parsed!", to_string(static_cast<LOAD_COMMAND_TYPES>(command.cmd)));

          load_command = std::unique_ptr<LoadCommand>{new LoadCommand{&command}};
        }
    }

    if (load_command != nullptr) {
      const uint8_t* content = this->stream_->peek_array<uint8_t>(loadcommands_offset, command.cmdsize, /* check */ false);
      if (content != nullptr) {
        load_command->data({
          content,
          content + command.cmdsize
        });
      }

      load_command->command_offset(loadcommands_offset);
      this->binary_->commands_.push_back(load_command.release());
    }
    loadcommands_offset += command.cmdsize;
  }
  this->binary_->available_command_space_ = low_fileoff - loadcommands_offset;
}


template<class MACHO_T>
void BinaryParser::parse_relocations(Section& section) {
  if (section.numberof_relocations() == 0) {
    LIEF_DEBUG("No relocations in {}", section.name());
    return;
  }

  LIEF_DEBUG("Parse '{}' relocations (#{:d})", section.name(), section.numberof_relocations());

  uint64_t current_reloc_offset = section.relocation_offset();
  size_t numberof_relocations = section.numberof_relocations();
  if (section.numberof_relocations() > BinaryParser::MAX_RELOCATIONS) {
    numberof_relocations = BinaryParser::MAX_RELOCATIONS;
    LIEF_WARN("Huge number of relocations (#{:d}). On the first #{:d} will be parsed",
        section.numberof_relocations(), numberof_relocations);

  }
  if (current_reloc_offset + numberof_relocations * 2 * sizeof(uint32_t) > this->stream_->size()) {
    LIEF_WARN("Relocations corrupted");
    return;
  }

  std::unique_ptr<RelocationObject> reloc{nullptr};
  for (size_t i = 0; i < numberof_relocations; ++i) {
    int32_t address = this->stream_->peek<int32_t>(current_reloc_offset);
    bool is_scattered = static_cast<bool>(address & R_SCATTERED);

    if (is_scattered) {
      const scattered_relocation_info* reloc_info = &this->stream_->peek<scattered_relocation_info>(current_reloc_offset);
      reloc = std::unique_ptr<RelocationObject>{new RelocationObject{reloc_info}};
      reloc->section_ = &section;
    } else {
      const relocation_info* reloc_info = &this->stream_->peek<relocation_info>(current_reloc_offset);
      reloc = std::unique_ptr<RelocationObject>{new RelocationObject{reloc_info}};
      reloc->section_ = &section;

      if (reloc_info->r_extern == 1 and reloc_info->r_symbolnum != R_ABS) {
        if (reloc_info->r_symbolnum < this->binary_->symbols().size()) {
          Symbol& symbol = this->binary_->symbols()[reloc_info->r_symbolnum];
          reloc->symbol_ = &symbol;

          LIEF_DEBUG("Symbol: {}", symbol.name());
        } else {
          LIEF_WARN("Relocation #{:d} of {} symbol index is out-of-bound", i, section.name());
        }
      }

      if (reloc_info->r_extern == 0) {
        if (reloc_info->r_symbolnum < this->binary_->sections().size()) {
          Section& relsec = this->binary_->sections()[reloc_info->r_symbolnum];
          reloc->section_ = &relsec;

          LIEF_DEBUG("Section: {}", relsec.name());
        } else {
          LIEF_WARN("Relocation #{:d} of {} seems corrupted", i, section.name());
        }
      }
    }

    if (reloc) {
      if (not reloc->has_section()) {
        reloc->section_ = &section;
      }
      reloc->architecture_ = this->binary_->header().cpu_type();
      RelocationObject *r = reloc.release();
      auto&& result = section.relocations_.emplace(r);
      if (not result.second) { // Not inserted (Relocation already present)
        delete r;
      }
    }

    current_reloc_offset += 2 * sizeof(uint32_t);
  }

}

template<class MACHO_T>
void BinaryParser::parse_dyldinfo_rebases() {
  using pint_t = typename MACHO_T::uint;

  DyldInfo& dyldinfo = this->binary_->dyld_info();
  uint32_t offset = std::get<0>(dyldinfo.rebase());
  uint32_t size   = std::get<1>(dyldinfo.rebase());

  if (offset == 0 or size == 0) {
    return;
  }

  try {
    const uint8_t* raw_rebase = this->stream_->peek_array<uint8_t>(offset, size, /* check */ false);
    if (raw_rebase != nullptr) {
      dyldinfo.rebase_opcodes({raw_rebase, raw_rebase + size});
    }
  } catch (const exception& e) {
    LIEF_WARN("{}", e.what());
  }

  uint64_t end_offset = offset + size;

  bool     done = false;
  uint8_t  type = 0;
  uint32_t segment_index = 0;
  uint64_t segment_offset = 0;
  uint32_t count = 0;
  uint32_t skip = 0;

  it_segments segments = this->binary_->segments();
  const SegmentCommand* current_segmment = nullptr;

  this->stream_->setpos(offset);

  while (not done and this->stream_->pos() < end_offset) {
    uint8_t imm    = this->stream_->peek<uint8_t>() & REBASE_IMMEDIATE_MASK;
    uint8_t opcode = this->stream_->read<uint8_t>() & REBASE_OPCODE_MASK;

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
          segment_index   = imm;
          segment_offset  = this->stream_->read_uleb128();

          if (segment_index < segments.size()) {
            current_segmment = &segments[segment_index];
          } else {
            LIEF_ERR("REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: Bad index");
            done = true;
          }

          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_ADD_ADDR_ULEB:
        {
          segment_offset += this->stream_->read_uleb128();

          if (current_segmment == nullptr or segment_offset > current_segmment->file_size()) {
            LIEF_WARN("REBASE_OPCODE_ADD_ADDR_ULEB: Bad offset (0x{:x} > 0x{:x})",
              segment_offset, current_segmment->file_size());
          }

          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
        {
          segment_offset += (imm * sizeof(pint_t));

          if (current_segmment == nullptr or segment_offset > current_segmment->file_size()) {
            LIEF_WARN("REBASE_OPCODE_ADD_ADDR_IMM_SCALED: Bad offset (0x{:x} > 0x{:x})",
              segment_offset, current_segmment->file_size());
          }
          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_IMM_TIMES:
        {
          for (size_t i = 0; i < imm; ++i) {
            this->do_rebase<MACHO_T>(type, segment_index, segment_offset, segments);
            segment_offset += sizeof(pint_t);

            if (current_segmment == nullptr or segment_offset > current_segmment->file_size()) {
              LIEF_WARN("REBASE_OPCODE_DO_REBASE_IMM_TIMES: Bad offset (0x{:x} > 0x{:x})",
                segment_offset, current_segmment->file_size());
            }
          }
          break;
        }
      case REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
        {

          count = this->stream_->read_uleb128();
          for (size_t i = 0; i < count; ++i) {

            if (current_segmment == nullptr or segment_offset > current_segmment->file_size()) {
              LIEF_WARN("REBASE_OPCODE_DO_REBASE_ULEB_TIMES: Bad offset (0x{:x} > 0x{:x})",
                segment_offset, current_segmment->file_size());
            }
            this->do_rebase<MACHO_T>(type, segment_index, segment_offset, segments);
            segment_offset += sizeof(pint_t);
          }
          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
        {

          if (current_segmment == nullptr or segment_offset > current_segmment->file_size()) {
              LIEF_WARN("REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: Bad offset (0x{:x} > 0x{:x})",
                segment_offset, current_segmment->file_size());
          }
          this->do_rebase<MACHO_T>(type, segment_index, segment_offset, segments);

          segment_offset += this->stream_->read_uleb128() + sizeof(pint_t);

          break;
        }

      case REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
        {
          // Count
          count = this->stream_->read_uleb128();

          // Skip
          skip = this->stream_->read_uleb128();


          for (size_t i = 0; i < count; ++i) {

            if (current_segmment == nullptr or segment_offset > current_segmment->file_size()) {
              LIEF_WARN("REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: Bad offset (0x{:x} > 0x{:x})",
                segment_offset, current_segmment->file_size());
            }
            this->do_rebase<MACHO_T>(type, segment_index, segment_offset, segments);
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
}


template<class MACHO_T>
void BinaryParser::parse_dyldinfo_binds() {

  try {
    this->parse_dyldinfo_generic_bind<MACHO_T>();
  } catch (const exception& e) {
    throw corrupted(e.what());
  }


  try {
    this->parse_dyldinfo_weak_bind<MACHO_T>();
  } catch (const exception& e) {
    throw corrupted(e.what());
  }


  try {
    this->parse_dyldinfo_lazy_bind<MACHO_T>();
  } catch (const exception& e) {
    throw corrupted(e.what());
  }

}

// Generic bindings
// ================
template<class MACHO_T>
void BinaryParser::parse_dyldinfo_generic_bind() {
  using pint_t = typename MACHO_T::uint;

  DyldInfo& dyldinfo = this->binary_->dyld_info();

  uint32_t offset = std::get<0>(dyldinfo.bind());
  uint32_t size   = std::get<1>(dyldinfo.bind());

  if (offset == 0 or size == 0) {
    return;
  }

  try {
    const uint8_t* raw_binding = this->stream_->peek_array<uint8_t>(offset, size, /* check */ false);

    if (raw_binding != nullptr) {
      dyldinfo.bind_opcodes({raw_binding, raw_binding + size});
    }
  } catch (const exception& e) {
    LIEF_WARN("{}", e.what());
  }

  uint64_t end_offset = offset + size;

  uint8_t     type = 0;
  uint8_t     segment_idx = 0;
  uint64_t    segment_offset = 0;
  std::string symbol_name = "";
  int         library_ordinal = 0;

  int64_t     addend = 0;
  uint32_t    count = 0;
  uint32_t    skip = 0;

  bool        is_weak_import = false;
  bool        done = false;

  size_t ordinal_table_size     = 0;
  bool use_threaded_rebase_bind = false;
  uint8_t symbol_flags          = 0;
  std::vector<ThreadedBindData> ordinal_table;

  it_segments segments = this->binary_->segments();
  this->stream_->setpos(offset);
  while (not done and this->stream_->pos() < end_offset) {
    uint8_t imm = this->stream_->peek<uint8_t>() & BIND_IMMEDIATE_MASK;
    BIND_OPCODES opcode = static_cast<BIND_OPCODES>(this->stream_->read<uint8_t>() & BIND_OPCODE_MASK);

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

          library_ordinal = this->stream_->read_uleb128();

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
          symbol_name = this->stream_->read_string();
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
          addend = this->stream_->read_sleb128();
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        {
          segment_idx    = imm;
          segment_offset = this->stream_->read_uleb128();
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_ADD_ADDR_ULEB:
        {
          segment_offset += this->stream_->read_uleb128();
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_DO_BIND:
        {
          if (not use_threaded_rebase_bind) {
            this->do_bind<MACHO_T>(
                BINDING_CLASS::BIND_CLASS_STANDARD,
                type,
                segment_idx,
                segment_offset,
                symbol_name,
                library_ordinal,
                addend,
                is_weak_import,
                false,
                segments);
            segment_offset += sizeof(pint_t);
          } else {
            ordinal_table.push_back(ThreadedBindData{symbol_name, addend, library_ordinal, symbol_flags, type});
          }
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        {
          this->do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_STANDARD,
              type,
              segment_idx,
              segment_offset,
              symbol_name,
              library_ordinal,
              addend,
              is_weak_import,
              false,
              segments);
          segment_offset += this->stream_->read_uleb128() + sizeof(pint_t);
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        {
          this->do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_STANDARD,
              type,
              segment_idx,
              segment_offset,
              symbol_name,
              library_ordinal,
              addend,
              is_weak_import,
              false,
              segments);
          segment_offset += imm * sizeof(pint_t) + sizeof(pint_t);
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
        {
          count = this->stream_->read_uleb128();
          skip  = this->stream_->read_uleb128();

          for (size_t i = 0; i < count; ++i) {
            this->do_bind<MACHO_T>(
                BINDING_CLASS::BIND_CLASS_STANDARD,
                type,
                segment_idx,
                segment_offset,
                symbol_name,
                library_ordinal,
                addend,
                is_weak_import,
                false,
                segments);
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
                  const std::vector<uint8_t>& content = current_segment.content();
                  if (segment_offset >= content.size() or segment_offset + sizeof(uint64_t) >= content.size()) {
                    LIEF_WARN("Bad segment offset (0x{:x})", segment_offset);
                    delta = 0; // exit from de do ... while
                    break;
                  }
                  auto value = *reinterpret_cast<const uint64_t*>(content.data() + segment_offset);
                  bool is_rebase = (value & (static_cast<uint64_t>(1) << 62)) == 0;

                  if (is_rebase) {
                    //LIEF_WARN("do rebase for addr: 0x{:x} vs 0x{:x}", address, current_segment)
                    this->do_rebase<MACHO_T>(static_cast<uint8_t>(REBASE_TYPES::REBASE_TYPE_POINTER),
                                             segment_idx, segment_offset, segments);
                  } else {
                    uint16_t ordinal = value & 0xFFFF;
                    if (ordinal >= ordinal_table_size or ordinal >= ordinal_table.size()) {
                      LIEF_WARN("bind ordinal ({:d}) is out of range (max={:d}) for disk pointer 0x{:04x} in "
                                "segment '{}' (segment offset: 0x{:04x})", ordinal, ordinal_table_size, value,
                                current_segment.name(), segment_offset);
                      break;
                    }
                    if (address < current_segment.virtual_address() or
                        address >= (current_segment.virtual_address() + current_segment.virtual_size())) {
                      LIEF_WARN("Bad binding address");
                      break;
                    }
                    const ThreadedBindData& th_bind_data = ordinal_table[ordinal];
                    this->do_bind<MACHO_T>(
                        BINDING_CLASS::BIND_CLASS_THREADED,
                        th_bind_data.type,
                        segment_idx,
                        segment_offset,
                        th_bind_data.symbol_name,
                        th_bind_data.library_ordinal,
                        th_bind_data.addend,
                        th_bind_data.symbol_flags & BIND_SYMBOL_FLAGS_WEAK_IMPORT,
                        false,
                        segments);
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
                count = this->stream_->read_uleb128();
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
  if (use_threaded_rebase_bind) {
    dyldinfo.binding_encoding_version_ = DyldInfo::BINDING_ENCODING_VERSION::V2;
  } else {
    dyldinfo.binding_encoding_version_ = DyldInfo::BINDING_ENCODING_VERSION::V1;
  }

}

// Weak binding
// ============
template<class MACHO_T>
void BinaryParser::parse_dyldinfo_weak_bind() {
  using pint_t = typename MACHO_T::uint;

  DyldInfo& dyldinfo = this->binary_->dyld_info();

  uint32_t offset = std::get<0>(dyldinfo.weak_bind());
  uint32_t size   = std::get<1>(dyldinfo.weak_bind());

  if (offset == 0 or size == 0) {
    return;
  }

  try {
    const uint8_t* raw_binding = this->stream_->peek_array<uint8_t>(offset, size, /* check */ false);

    if (raw_binding != nullptr) {
      dyldinfo.weak_bind_opcodes({raw_binding, raw_binding + size});
    }
  } catch (const exception& e) {
    LIEF_WARN("{}", e.what());
  }

  uint64_t end_offset = offset + size;

  uint8_t     type = 0;
  uint8_t     segment_idx = 0;
  uint64_t    segment_offset = 0;
  std::string symbol_name = "";

  int64_t     addend = 0;
  uint32_t    count = 0;
  uint32_t    skip = 0;

  bool        is_weak_import = true;
  bool        is_non_weak_definition = false;
  bool        done = false;

  it_segments segments = this->binary_->segments();

  this->stream_->setpos(offset);

  while (not done and this->stream_->pos() < end_offset) {
    uint8_t imm    = this->stream_->peek<uint8_t>() & BIND_IMMEDIATE_MASK;
    BIND_OPCODES opcode = static_cast<BIND_OPCODES>(this->stream_->read<uint8_t>() & BIND_OPCODE_MASK);

    switch (opcode) {
      case BIND_OPCODES::BIND_OPCODE_DONE:
        {
          done = true;
          break;
        }


      case BIND_OPCODES::BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        {
          symbol_name = this->stream_->read_string();

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
          addend = this->stream_->read_sleb128();
          break;
        }


      case BIND_OPCODES::BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        {
          segment_idx    = imm;
          segment_offset = this->stream_->read_uleb128();

          break;
        }


      case BIND_OPCODES::BIND_OPCODE_ADD_ADDR_ULEB:
        {
          segment_offset += this->stream_->read_uleb128();
          break;
        }


      case BIND_OPCODES::BIND_OPCODE_DO_BIND:
        {
          this->do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_WEAK,
              type,
              segment_idx,
              segment_offset,
              symbol_name,
              0,
              addend,
              is_weak_import,
              is_non_weak_definition,
              segments);
          segment_offset += sizeof(pint_t);
          break;
        }


      case BIND_OPCODES::BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        {
          this->do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_WEAK,
              type,
              segment_idx,
              segment_offset,
              symbol_name,
              0,
              addend,
              is_weak_import,
              is_non_weak_definition,
              segments);
          segment_offset += this->stream_->read_uleb128() + sizeof(pint_t);
          break;
        }


      case BIND_OPCODES::BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        {
          this->do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_WEAK,
              type,
              segment_idx,
              segment_offset,
              symbol_name,
              0,
              addend,
              is_weak_import,
              is_non_weak_definition,
              segments);
          segment_offset += imm * sizeof(pint_t) + sizeof(pint_t);
          break;
        }


      case BIND_OPCODES::BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
        {

          // Count
          count   = this->stream_->read_uleb128();

          // Skip
          skip    = this->stream_->read_uleb128();

          for (size_t i = 0; i < count; ++i) {
            this->do_bind<MACHO_T>(
                BINDING_CLASS::BIND_CLASS_WEAK,
                type,
                segment_idx,
                segment_offset,
                symbol_name,
                0,
                addend,
                is_weak_import,
                is_non_weak_definition,
                segments);
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

}

// Lazy binding
// ============
template<class MACHO_T>
void BinaryParser::parse_dyldinfo_lazy_bind() {
  using pint_t = typename MACHO_T::uint;

  DyldInfo& dyldinfo = this->binary_->dyld_info();

  uint32_t offset = std::get<0>(dyldinfo.lazy_bind());
  uint32_t size   = std::get<1>(dyldinfo.lazy_bind());

  if (offset == 0 or size == 0) {
    return;
  }

  try {
    const uint8_t* raw_binding = this->stream_->peek_array<uint8_t>(offset, size, /* check */ false);

    if (raw_binding != nullptr) {
      dyldinfo.lazy_bind_opcodes({raw_binding, raw_binding + size});
    }
  } catch (const exception& e) {
    LIEF_WARN("{}", e.what());
  }

  uint64_t current_offset = offset;
  uint64_t end_offset     = offset + size;

  //uint32_t    lazy_offset     = 0;
  uint8_t     segment_idx     = 0;
  uint64_t    segment_offset  = 0;
  std::string symbol_name     = "";
  int32_t     library_ordinal = 0;
  int64_t     addend          = 0;
  bool        is_weak_import  = false;
  uint64_t    start_offset    = 0;

  it_segments segments = this->binary_->segments();
  this->stream_->setpos(offset);
  while (this->stream_->pos() < end_offset) {
    uint8_t imm    = this->stream_->peek<uint8_t>() & BIND_IMMEDIATE_MASK;
    BIND_OPCODES opcode = static_cast<BIND_OPCODES>(this->stream_->read<uint8_t>() & BIND_OPCODE_MASK);
    current_offset += sizeof(uint8_t);

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
          library_ordinal = this->stream_->read_uleb128();
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
          symbol_name = this->stream_->read_string();

          if ((imm & BIND_SYMBOL_FLAGS_WEAK_IMPORT) != 0) {
            is_weak_import = true;
          } else {
            is_weak_import = false;
          }
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_ADDEND_SLEB:
        {
          addend = this->stream_->read_sleb128();;
          break;
        }

      case BIND_OPCODES::BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        {
          segment_idx    = imm;
          segment_offset = this->stream_->read_uleb128();

          break;
        }

      case BIND_OPCODES::BIND_OPCODE_DO_BIND:
        {
          this->do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_LAZY,
              static_cast<uint8_t>(BIND_TYPES::BIND_TYPE_POINTER),
              segment_idx,
              segment_offset,
              symbol_name,
              library_ordinal,
              addend,
              is_weak_import,
              false,
              segments, start_offset);
          start_offset = this->stream_->pos() - offset + 1;
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
}

template<class MACHO_T>
void BinaryParser::do_bind(BINDING_CLASS cls,
        uint8_t type,
        uint8_t segment_idx,
        uint64_t segment_offset,
        const std::string& symbol_name,
        int32_t ord,
        int64_t addend,
        bool is_weak,
        bool is_non_weak_definition,
        it_segments& segments,
        uint64_t offset) {


  if (segment_idx >= segments.size()) {
    LIEF_ERR("Wrong index ({:d})", segment_idx);
    return;
  }
  SegmentCommand& segment = segments[segment_idx];
  // Address to bind
  uint64_t address = segment.virtual_address() + segment_offset;

  if (address > (segment.virtual_address() + segment.virtual_size())) {
    LIEF_ERR("Bad address: 0x{:x}", address);
    return;
  }


  // Create a BindingInfo object
  std::unique_ptr<BindingInfo> binding_info{
    new BindingInfo{cls, static_cast<BIND_TYPES>(type),
                    address, addend, ord,
                    is_weak, is_non_weak_definition, offset}};
  binding_info->segment_ = &segment;


  it_libraries libraries = this->binary_->libraries();
  if (0 < ord and static_cast<size_t>(ord) <= libraries.size()) {
    binding_info->library_ = &libraries[ord - 1];
  }

  Symbol* symbol = nullptr;
  auto search = this->memoized_symbols_.find(symbol_name);
  if (search != this->memoized_symbols_.end()) {
    symbol = search->second;
  } else {
    symbol = this->binary_->get_symbol(symbol_name);
  }
  if (symbol != nullptr) {
    binding_info->symbol_ = symbol;
    symbol->binding_info_ = binding_info.get();
  } else {
    LIEF_ERR("New symbol found: {}", symbol_name);
  }


  this->binary_->dyld_info().binding_info_.push_back(binding_info.release());
  LIEF_DEBUG("{} {} - {}", to_string(cls), segment.name(), symbol_name);
}

template<class MACHO_T>
void BinaryParser::do_rebase(uint8_t type, uint8_t segment_idx, uint64_t segment_offset,
                             const it_segments& segments) {
  using pint_t = typename MACHO_T::uint;

  if (segment_idx >= segments.size()) {
    LIEF_ERR("Wrong index ({:d})", segment_idx);
    return;
  }

  SegmentCommand& segment = segments[segment_idx];
  uint64_t address = segment.virtual_address() + segment_offset;

  if (address > (segment.virtual_address() + segment.virtual_size())) {
    LIEF_ERR("Bad rebase address: 0x{:x}", address);
    return;
  }

  // Check if a relocation already exists:
  std::unique_ptr<RelocationDyld> new_relocation{new RelocationDyld{address, type}};
  auto result = segment.relocations_.emplace(new_relocation.get());
  Relocation* reloc = *result.first;

  // result.second is true if the insertion succeed
  if (result.second) {
    new_relocation.release();
  } else {
    delete new_relocation.release();
  }
  reloc->architecture_ = this->binary_->header().cpu_type();

  // Tie section and segment
  reloc->segment_ = &segment;
  Section* section = this->binary_->section_from_virtual_address(address);
  if (section == nullptr) {
    throw not_found("Unable to find section");
  }
  reloc->section_ = section;

  // Tie symbol
  const auto it_symbol = this->memoized_symbols_by_address_.find(address);
  if (it_symbol != this->memoized_symbols_by_address_.end()) {
    reloc->symbol_ = it_symbol->second;
  }

  switch (static_cast<REBASE_TYPES>(type)) {
    case REBASE_TYPES::REBASE_TYPE_POINTER:
      {
        reloc->size_ = sizeof(pint_t) * 8;
        break;
      }


    case REBASE_TYPES::REBASE_TYPE_TEXT_ABSOLUTE32:
    case REBASE_TYPES::REBASE_TYPE_TEXT_PCREL32:
      {
        reloc->size_ = sizeof(uint32_t) * 8;
        break;
      }
    case REBASE_TYPES::REBASE_TYPE_THREADED:
      {
        reloc->size_ = sizeof(pint_t) * 8;
        break;
      }

    default:
      {
        LIEF_ERR("Unsuported relocation type: 0x{:x}", type);
      }
  }
}




}
}
