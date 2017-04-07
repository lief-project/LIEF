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
#include "easylogging++.h"

namespace LIEF {
namespace MachO {


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

      case LOAD_COMMAND_TYPES::LC_TWOLEVEL_HINTS:
        {
          LOG(DEBUG) << "[+] Parsing LC_TWOLEVEL_HINTS";

          load_command = new LoadCommand{command};
          break;
        }

      case LOAD_COMMAND_TYPES::LC_SUB_FRAMEWORK:
        {
          LOG(DEBUG) << "[+] Parsing LC_SUB_FRAMEWORK";

          load_command = new LoadCommand{command};
          break;
        }

      case LOAD_COMMAND_TYPES::LC_SUB_UMBRELLA:
        {
          LOG(DEBUG) << "[+] Parsing LC_SUB_UMBRELLA";

          load_command = new LoadCommand{command};
          break;
        }

      case LOAD_COMMAND_TYPES::LC_SUB_LIBRARY:
        {
          LOG(DEBUG) << "[+] Parsing LC_SUB_LIBRARY";

          load_command = new LoadCommand{command};
          break;
        }

      case LOAD_COMMAND_TYPES::LC_SUB_CLIENT:
        {
          LOG(DEBUG) << "[+] Parsing LC_SUB_CLIENT";

          load_command = new LoadCommand{command};
          break;
        }

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

      case LOAD_COMMAND_TYPES::LC_FUNCTION_STARTS:
        {
          LOG(DEBUG) << "[+] Parsing LC_FUNCTION_STARTS";
          load_command = new LoadCommand{command};
          break;
        }

      case LOAD_COMMAND_TYPES::LC_CODE_SIGNATURE:
        {
          LOG(DEBUG) << "[+] Parsing LC_CODE_SIGNATURE";
          load_command = new LoadCommand{command};
          break;
        }
      case LOAD_COMMAND_TYPES::LC_ENCRYPTION_INFO_64:{
          LOG(DEBUG) << "[+] Parsing LC_ENCRYPTION_INFO_64";
          const encryption_info_command_64* cmd =
            reinterpret_cast<const encryption_info_command_64*>(
              this->stream_->read(loadcommands_offset, sizeof(encryption_info_command_64)));

          load_command = new EncryptionInfoCommand{cmd};
          break;
        }
      case LOAD_COMMAND_TYPES::LC_ENCRYPTION_INFO:{
          LOG(DEBUG) << "[+] Parsing LC_ENCRYPTION_INFO";
          const encryption_info_command_32* cmd =
            reinterpret_cast<const encryption_info_command_32*>(
              this->stream_->read(loadcommands_offset, sizeof(encryption_info_command_32)));

          load_command = new EncryptionInfoCommand{cmd};
          break;
        }
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
}
}
