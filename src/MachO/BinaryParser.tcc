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
#include "LIEF/MachO/DyldInfo.hpp"
#include "LIEF/MachO/FunctionStarts.hpp"
#include "LIEF/MachO/SourceVersion.hpp"
#include "LIEF/MachO/VersionMin.hpp"

#include "easylogging++.h"

namespace LIEF {
namespace MachO {

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
      LOG(WARNING) << e.what();
    }
  }
}

template<class MACHO_T>
void BinaryParser::parse_header(void) {
  using header_t = typename MACHO_T::header;
  this->binary_->header_ = {reinterpret_cast<const header_t*>(this->stream_->read(0, sizeof(header_t)))};
}


template<class MACHO_T>
void BinaryParser::parse_load_commands(void) {
  using header_t          = typename MACHO_T::header;
  using segment_command_t = typename MACHO_T::segment_command;
  using section_t         = typename MACHO_T::section;

  LOG(DEBUG) << "[+] Building Load commands";
  uint64_t loadcommands_offset = sizeof(header_t);

  for (size_t i = 0; i < this->binary_->header().nb_cmds(); ++i) {
    const load_command* command = reinterpret_cast<const load_command*>(
        this->stream_->read(loadcommands_offset, sizeof(load_command)));

    LoadCommand* load_command = nullptr;
    switch (command->cmd) {

      // ===============
      // Segment command
      // ===============
      case LOAD_COMMAND_TYPES::LC_SEGMENT_64:
      case LOAD_COMMAND_TYPES::LC_SEGMENT:
        {
          uint64_t local_offset = loadcommands_offset;
          load_command = new SegmentCommand{
                reinterpret_cast<const segment_command_t*>(
                    this->stream_->read(loadcommands_offset, sizeof(segment_command_t)))};

          local_offset += sizeof(segment_command_t);

          SegmentCommand* segment = dynamic_cast<SegmentCommand*>(load_command);

          const uint8_t* content = static_cast<const uint8_t*>(
            this->stream_->read(segment->file_offset(), segment->file_size()));

          segment->content({
              content,
              content + segment->file_size()
              });

          // --------
          // Sections
          // --------
          for (size_t j = 0; j < segment->numberof_sections(); ++j) {
            Section section{reinterpret_cast<const section_t*>(this->stream_->read(local_offset, sizeof(section_t)))};
            section.segment_ = segment;
            segment->sections_.push_back(std::move(section));
            local_offset += sizeof(section_t);
          }
          break;
        }


      // =============
      // DyLib Command
      // =============
      case LOAD_COMMAND_TYPES::LC_LOAD_WEAK_DYLIB:
      case LOAD_COMMAND_TYPES::LC_ID_DYLIB:
      case LOAD_COMMAND_TYPES::LC_LOAD_DYLIB:
        {
          const dylib_command* cmd =
            reinterpret_cast<const dylib_command*>(
              this->stream_->read(loadcommands_offset, sizeof(dylib_command)));

          load_command = new DylibCommand{cmd};
          const uint32_t str_name_offset = cmd->dylib.name;
          std::string name = {this->stream_->read_string(loadcommands_offset + str_name_offset)};

          dynamic_cast<DylibCommand*>(load_command)->name(name);
          break;
        }

      // ====
      // UUID
      // ====
      case LOAD_COMMAND_TYPES::LC_UUID:
        {
          LOG(DEBUG) << "[+] Building UUID";
          const uuid_command* cmd =
            reinterpret_cast<const uuid_command*>(
              this->stream_->read(loadcommands_offset, sizeof(uuid_command)));
          load_command = new UUIDCommand{cmd};
          break;
        }

      // ==============
      // Dynamic Linker
      // ==============
      case LOAD_COMMAND_TYPES::LC_LOAD_DYLINKER:
      case LOAD_COMMAND_TYPES::LC_ID_DYLINKER:
        {
          const dylinker_command* cmd =
            reinterpret_cast<const dylinker_command*>(
              this->stream_->read(loadcommands_offset, sizeof(dylinker_command)));

          const uint32_t linker_name_offset = cmd->name;
          std::string name = {this->stream_->read_string(
             loadcommands_offset +
             linker_name_offset)};

          load_command = new DylinkerCommand{cmd};
          dynamic_cast<DylinkerCommand*>(load_command)->name(name);
          break;
        }

      // ==============
      // Prebound Dylib
      // ==============
      case LOAD_COMMAND_TYPES::LC_PREBOUND_DYLIB:
        {
          LOG(DEBUG) << "[+] Parsing LC_PREBOUND_DYLIB";

          load_command = new LoadCommand{command};
          const prebound_dylib_command* cmd =
            reinterpret_cast<const prebound_dylib_command*>(
              this->stream_->read(loadcommands_offset, sizeof(prebound_dylib_command)));


          std::string name = {this->stream_->read_string(
             loadcommands_offset +
             cmd->name)};

          //uint32_t sizeof_linked_modules = (cmd->nmodules / 8) + (cmd->nmodules % 8);

          break;
        }

      // ======
      // Thread
      // ======
      case LOAD_COMMAND_TYPES::LC_THREAD:
      case LOAD_COMMAND_TYPES::LC_UNIXTHREAD:
        {
          LOG(DEBUG) << "[+] Parsing LC_THREAD";

          load_command = new LoadCommand{command};
          const thread_command* cmd =
            reinterpret_cast<const thread_command*>(
              this->stream_->read(loadcommands_offset, sizeof(thread_command)));

          LOG(DEBUG) << "FLAVOR: " << cmd->flavor << std::endl
                     << "COUNT:  " << cmd->count;
          break;
        }

      // ===============
      // Routine command
      // ===============
      case LOAD_COMMAND_TYPES::LC_ROUTINES:
      case LOAD_COMMAND_TYPES::LC_ROUTINES_64:
        {

          LOG(DEBUG) << "[+] Parsing LC_ROUTINE";

          load_command = new LoadCommand{command};
          break;
        }

      // =============
      // Symbols table
      // =============
      case LOAD_COMMAND_TYPES::LC_SYMTAB:
        {
          using nlist_t = typename MACHO_T::nlist;
          LOG(DEBUG) << "[+] Parsing symbols";

          const symtab_command* cmd =
            reinterpret_cast<const symtab_command*>(
              this->stream_->read(loadcommands_offset, sizeof(symtab_command)));


          load_command = new SymbolCommand{cmd};


          const nlist_t* nlist = reinterpret_cast<const nlist_t*>(
              this->stream_->read(cmd->symoff, sizeof(nlist_t)));

          for (size_t j = 0; j < cmd->nsyms; ++j) {
            Symbol* symbol = new Symbol{&nlist[j]};
            uint32_t idx = nlist[j].n_strx;
            if (idx > 0) {
              symbol->name(
                  this->stream_->read_string(cmd->stroff + idx));
            }
            this->binary_->symbols_.push_back(symbol);
          }

          break;
        }

      // ===============
      // Dynamic Symbols
      // ===============
      case LOAD_COMMAND_TYPES::LC_DYSYMTAB:
        {
          LOG(DEBUG) << "[+] Parsing dynamic symbols";
          const dysymtab_command* cmd =
            reinterpret_cast<const dysymtab_command*>(
              this->stream_->read(loadcommands_offset, sizeof(dysymtab_command)));

          load_command = new DynamicSymbolCommand{cmd};
          break;
        }

      // ===============
      // Dyd Info
      // ===============
      case LOAD_COMMAND_TYPES::LC_DYLD_INFO:
      case LOAD_COMMAND_TYPES::LC_DYLD_INFO_ONLY:
        {
          LOG(DEBUG) << "[+] Parsing dyld information";
          const dyld_info_command* cmd =
            reinterpret_cast<const dyld_info_command*>(
              this->stream_->read(loadcommands_offset, sizeof(dyld_info_command)));

          load_command = new DyldInfo{cmd};
          break;
        }

      // ===============
      // Source Version
      // ===============
      case LOAD_COMMAND_TYPES::LC_SOURCE_VERSION:
        {
          LOG(DEBUG) << "[+] Parsing LC_SOURCE_VERSION";

          const source_version_command* cmd =
            reinterpret_cast<const source_version_command*>(
              this->stream_->read(loadcommands_offset, sizeof(version_min_command)));

          load_command = new SourceVersion{cmd};
          LOG(DEBUG) << "Version: " << std::hex << cmd->version;
          break;
        }

      case LOAD_COMMAND_TYPES::LC_VERSION_MIN_MACOSX:
      case LOAD_COMMAND_TYPES::LC_VERSION_MIN_IPHONEOS:
        {
          LOG(DEBUG) << "[+] Parsing " << to_string(static_cast<LOAD_COMMAND_TYPES>(command->cmd));

          const version_min_command* cmd =
            reinterpret_cast<const version_min_command*>(
              this->stream_->read(loadcommands_offset, sizeof(version_min_command)));
          LOG(DEBUG) << "Version: " << std::hex << cmd->version;
          LOG(DEBUG) << "SDK: "     << std::hex << cmd->sdk;

          load_command = new VersionMin{cmd};
          break;
        }




      //case LOAD_COMMAND_TYPES::LC_TWOLEVEL_HINTS:
      //  {
      //    LOG(DEBUG) << "[+] Parsing LC_TWOLEVEL_HINTS";

      //    load_command = new LoadCommand{command};
      //    break;
      //  }

      //case LOAD_COMMAND_TYPES::LC_SUB_FRAMEWORK:
      //  {
      //    LOG(DEBUG) << "[+] Parsing LC_SUB_FRAMEWORK";

      //    load_command = new LoadCommand{command};
      //    break;
      //  }

      //case LOAD_COMMAND_TYPES::LC_SUB_UMBRELLA:
      //  {
      //    LOG(DEBUG) << "[+] Parsing LC_SUB_UMBRELLA";

      //    load_command = new LoadCommand{command};
      //    break;
      //  }

      //case LOAD_COMMAND_TYPES::LC_SUB_LIBRARY:
      //  {
      //    LOG(DEBUG) << "[+] Parsing LC_SUB_LIBRARY";

      //    load_command = new LoadCommand{command};
      //    break;
      //  }

      //case LOAD_COMMAND_TYPES::LC_SUB_CLIENT:
      //  {
      //    LOG(DEBUG) << "[+] Parsing LC_SUB_CLIENT";

      //    load_command = new LoadCommand{command};
      //    break;
      //  }

      // =======
      // LC_MAIN
      // =======
      case LOAD_COMMAND_TYPES::LC_MAIN:
        {
          LOG(DEBUG) << "[+] Parsing LC_MAIN";

          const entry_point_command* cmd =
            reinterpret_cast<const entry_point_command*>(
              this->stream_->read(loadcommands_offset, sizeof(entry_point_command)));

          load_command = new MainCommand{cmd};
          break;
        }

      // ==================
      // LC_FUNCTION_STARTS
      // ==================
      case LOAD_COMMAND_TYPES::LC_FUNCTION_STARTS:
        {
          LOG(DEBUG) << "[+] Parsing LC_FUNCTION_STARTS";
          const linkedit_data_command* cmd =
            reinterpret_cast<const linkedit_data_command*>(
              this->stream_->read(loadcommands_offset, sizeof(linkedit_data_command)));
          load_command = new FunctionStarts{cmd};

          uint64_t offset = cmd->dataoff;
          std::pair<uint64_t, uint64_t> value_delta;
          uint64_t value = 0;

          do {
            value_delta = BinaryParser::decode_uleb128(*this->stream_.get(), offset);
            if (std::get<0>(value_delta) == 0) {
              break;
            }
            value  += std::get<0>(value_delta);
            offset += std::get<1>(value_delta);

            LOG(DEBUG) << "Value: " << std::hex << value;
            dynamic_cast<FunctionStarts*>(load_command)->add_function(value);
          } while(offset < (cmd->dataoff + cmd->datasize) and std::get<0>(value_delta) > 0);

          break;
        }

      //case LOAD_COMMAND_TYPES::LC_CODE_SIGNATURE:
      //  {
      //    LOG(DEBUG) << "[+] Parsing LC_CODE_SIGNATURE";
      //    load_command = new LoadCommand{command};
      //    break;
      //  }

      default:
        {
          LOG(WARNING) << "Command '" << to_string(static_cast<LOAD_COMMAND_TYPES>(command->cmd))
                       << "' not parsed";

          load_command = new LoadCommand{command};
        }
    }

    if (load_command != nullptr) {
      const uint8_t* content = static_cast<const uint8_t*>(
        this->stream_->read(loadcommands_offset, command->cmdsize));

      load_command->data({
        content,
        content + command->cmdsize
      });

      load_command->command_offset(loadcommands_offset);
      this->binary_->commands_.push_back(load_command);
    }
    loadcommands_offset += command->cmdsize;
  }
}


template<class MACHO_T>
void BinaryParser::parse_relocations(Section& section) {
  if (section.numberof_relocations() == 0) {
    LOG(DEBUG) << "No relocations in " << section.name();
    return;
  }

  LOG(DEBUG) << "Parse '" << section.name() << "' relocations (" << std::dec << section.numberof_relocations() << ")";

  uint64_t current_reloc_offset = section.relocation_offset();
  section.relocations_.resize(section.numberof_relocations());
  for (size_t i = 0; i < section.numberof_relocations(); ++i) {
    int32_t address = this->stream_->read_integer<int32_t>(current_reloc_offset);
    bool is_scattered = static_cast<bool>(address & R_SCATTERED);
    if (is_scattered) {
      const scattered_relocation_info* reloc_info = reinterpret_cast<const scattered_relocation_info*>(
          this->stream_->read(current_reloc_offset, sizeof(scattered_relocation_info)));
      section.relocations_[i] = {reloc_info};
    } else {
      const relocation_info* reloc_info = reinterpret_cast<const relocation_info*>(
          this->stream_->read(current_reloc_offset, sizeof(relocation_info)));
      section.relocations_[i] = {reloc_info};

      if (reloc_info->r_extern == 1 and reloc_info->r_symbolnum != R_ABS) {
        if (reloc_info->r_symbolnum < this->binary_->symbols().size()) {
          Symbol& symbol = this->binary_->symbols()[reloc_info->r_symbolnum];
          Relocation& relocation = section.relocations()[i];
          relocation.symbol_ = &symbol;

          LOG(DEBUG) << "Symbol: " << symbol.name();
        } else {
          LOG(WARNING) << "Relocation #" << std::dec << i << " of " << section.name() << " symbol index is out-of-bound";
        }
      }

      if (reloc_info->r_extern == 0) {
        if (reloc_info->r_symbolnum < this->binary_->sections().size()) {
          Section& relsec = this->binary_->sections()[reloc_info->r_symbolnum];
          Relocation& relocation = section.relocations()[i];
          relocation.section_ = &relsec;

          LOG(DEBUG) << "Section: " << relsec.name();
        } else {
          LOG(WARNING) << "Relocation #" << std::dec << i << " of " << section.name() << " seems corrupted";
        }
      }
    }

    if (not section.relocations_[i].has_section()) {
      section.relocations_[i].section_ = &section;
    }
    section.relocations_[i].architecture_ = this->binary_->header().cpu_type();
    LOG(DEBUG) << section.relocations_.back();;
    current_reloc_offset += 2 * sizeof(uint32_t);
  }

}

}
}
