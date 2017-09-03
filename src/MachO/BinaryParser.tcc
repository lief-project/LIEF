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

#include "LIEF/MachO/DyldInfo.hpp"
#include "LIEF/MachO/FunctionStarts.hpp"
#include "LIEF/MachO/SourceVersion.hpp"
#include "LIEF/MachO/VersionMin.hpp"
#include "LIEF/MachO/Relocation.hpp"
#include "LIEF/MachO/RelocationObject.hpp"
#include "LIEF/MachO/RelocationDyld.hpp"


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

  if (this->binary_->has_dyld_info()) {

    try {
      this->parse_dyldinfo_binds<MACHO_T>();
    } catch (const exception& e) {
      LOG(WARNING) << e.what();
    }

    try {
      this->parse_dyldinfo_export();
    } catch (const exception& e) {
      LOG(WARNING) << e.what();
    }

    try {
      this->parse_dyldinfo_rebases<MACHO_T>();
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

  VLOG(VDEBUG) << "[+] Building Load commands";
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
          VLOG(VDEBUG) << "[+] Building UUID";
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
          VLOG(VDEBUG) << "[+] Parsing LC_PREBOUND_DYLIB";

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
          VLOG(VDEBUG) << "[+] Parsing LC_THREAD";

          load_command = new LoadCommand{command};
          const thread_command* cmd =
            reinterpret_cast<const thread_command*>(
              this->stream_->read(loadcommands_offset, sizeof(thread_command)));

          VLOG(VDEBUG) << "FLAVOR: " << cmd->flavor << std::endl
                     << "COUNT:  " << cmd->count;
          break;
        }

      // ===============
      // Routine command
      // ===============
      case LOAD_COMMAND_TYPES::LC_ROUTINES:
      case LOAD_COMMAND_TYPES::LC_ROUTINES_64:
        {

          VLOG(VDEBUG) << "[+] Parsing LC_ROUTINE";

          load_command = new LoadCommand{command};
          break;
        }

      // =============
      // Symbols table
      // =============
      case LOAD_COMMAND_TYPES::LC_SYMTAB:
        {
          using nlist_t = typename MACHO_T::nlist;
          VLOG(VDEBUG) << "[+] Parsing symbols";

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
          VLOG(VDEBUG) << "[+] Parsing dynamic symbols";
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
          VLOG(VDEBUG) << "[+] Parsing dyld information";
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
          VLOG(VDEBUG) << "[+] Parsing LC_SOURCE_VERSION";

          const source_version_command* cmd =
            reinterpret_cast<const source_version_command*>(
              this->stream_->read(loadcommands_offset, sizeof(version_min_command)));

          load_command = new SourceVersion{cmd};
          VLOG(VDEBUG) << "Version: " << std::hex << cmd->version;
          break;
        }

      case LOAD_COMMAND_TYPES::LC_VERSION_MIN_MACOSX:
      case LOAD_COMMAND_TYPES::LC_VERSION_MIN_IPHONEOS:
        {
          VLOG(VDEBUG) << "[+] Parsing " << to_string(static_cast<LOAD_COMMAND_TYPES>(command->cmd));

          const version_min_command* cmd =
            reinterpret_cast<const version_min_command*>(
              this->stream_->read(loadcommands_offset, sizeof(version_min_command)));
          VLOG(VDEBUG) << "Version: " << std::hex << cmd->version;
          VLOG(VDEBUG) << "SDK: "     << std::hex << cmd->sdk;

          load_command = new VersionMin{cmd};
          break;
        }




      //case LOAD_COMMAND_TYPES::LC_TWOLEVEL_HINTS:
      //  {
      //    VLOG(VDEBUG) << "[+] Parsing LC_TWOLEVEL_HINTS";

      //    load_command = new LoadCommand{command};
      //    break;
      //  }

      //case LOAD_COMMAND_TYPES::LC_SUB_FRAMEWORK:
      //  {
      //    VLOG(VDEBUG) << "[+] Parsing LC_SUB_FRAMEWORK";

      //    load_command = new LoadCommand{command};
      //    break;
      //  }

      //case LOAD_COMMAND_TYPES::LC_SUB_UMBRELLA:
      //  {
      //    VLOG(VDEBUG) << "[+] Parsing LC_SUB_UMBRELLA";

      //    load_command = new LoadCommand{command};
      //    break;
      //  }

      //case LOAD_COMMAND_TYPES::LC_SUB_LIBRARY:
      //  {
      //    VLOG(VDEBUG) << "[+] Parsing LC_SUB_LIBRARY";

      //    load_command = new LoadCommand{command};
      //    break;
      //  }

      //case LOAD_COMMAND_TYPES::LC_SUB_CLIENT:
      //  {
      //    VLOG(VDEBUG) << "[+] Parsing LC_SUB_CLIENT";

      //    load_command = new LoadCommand{command};
      //    break;
      //  }

      // =======
      // LC_MAIN
      // =======
      case LOAD_COMMAND_TYPES::LC_MAIN:
        {
          VLOG(VDEBUG) << "[+] Parsing LC_MAIN";

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
          VLOG(VDEBUG) << "[+] Parsing LC_FUNCTION_STARTS";
          const linkedit_data_command* cmd =
            reinterpret_cast<const linkedit_data_command*>(
              this->stream_->read(loadcommands_offset, sizeof(linkedit_data_command)));
          load_command = new FunctionStarts{cmd};

          uint64_t offset = cmd->dataoff;
          std::pair<uint64_t, uint64_t> value_delta;
          uint64_t value = 0;

          do {
            value_delta = this->stream_->read_uleb128(offset);
            if (std::get<0>(value_delta) == 0) {
              break;
            }
            value  += std::get<0>(value_delta);
            offset += std::get<1>(value_delta);

            VLOG(VDEBUG) << "Value: " << std::hex << value;
            dynamic_cast<FunctionStarts*>(load_command)->add_function(value);
          } while(offset < (cmd->dataoff + cmd->datasize) and std::get<0>(value_delta) > 0);

          break;
        }

      //case LOAD_COMMAND_TYPES::LC_CODE_SIGNATURE:
      //  {
      //    VLOG(VDEBUG) << "[+] Parsing LC_CODE_SIGNATURE";
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
    VLOG(VDEBUG) << "No relocations in " << section.name();
    return;
  }

  VLOG(VDEBUG) << "Parse '" << section.name() << "' relocations (" << std::dec << section.numberof_relocations() << ")";

  uint64_t current_reloc_offset = section.relocation_offset();
  size_t numberof_relocations = section.numberof_relocations();
  if (section.numberof_relocations() > BinaryParser::MAX_RELOCATIONS) {
    numberof_relocations = BinaryParser::MAX_RELOCATIONS;
    LOG(WARNING) << "Huge number of relocations (" << std::dec << section.relocation_offset() << "). "
                 << "Only the first " << std::dec << numberof_relocations << " will be parsed";

  }

  section.relocations_.reserve(numberof_relocations);
  for (size_t i = 0; i < numberof_relocations; ++i) {
    int32_t address = this->stream_->read_integer<int32_t>(current_reloc_offset);
    bool is_scattered = static_cast<bool>(address & R_SCATTERED);
    if (is_scattered) {
      const scattered_relocation_info* reloc_info = reinterpret_cast<const scattered_relocation_info*>(
          this->stream_->read(current_reloc_offset, sizeof(scattered_relocation_info)));
      section.relocations_.push_back(new RelocationObject{reloc_info});
    } else {
      const relocation_info* reloc_info = reinterpret_cast<const relocation_info*>(
          this->stream_->read(current_reloc_offset, sizeof(relocation_info)));
      section.relocations_.push_back(new RelocationObject{reloc_info});

      if (reloc_info->r_extern == 1 and reloc_info->r_symbolnum != R_ABS) {
        if (reloc_info->r_symbolnum < this->binary_->symbols().size()) {
          Symbol& symbol = this->binary_->symbols()[reloc_info->r_symbolnum];
          Relocation* relocation = section.relocations_.back();
          relocation->symbol_ = &symbol;

          VLOG(VDEBUG) << "Symbol: " << symbol.name();
        } else {
          LOG(WARNING) << "Relocation #" << std::dec << i << " of " << section.name() << " symbol index is out-of-bound";
        }
      }

      if (reloc_info->r_extern == 0) {
        if (reloc_info->r_symbolnum < this->binary_->sections().size()) {
          Section& relsec = this->binary_->sections()[reloc_info->r_symbolnum];
          Relocation* relocation = section.relocations_.back();
          relocation->section_ = &relsec;

          VLOG(VDEBUG) << "Section: " << relsec.name();
        } else {
          LOG(WARNING) << "Relocation #" << std::dec << i << " of " << section.name() << " seems corrupted";
        }
      }
    }

    if (not section.relocations_[i]->has_section()) {
      section.relocations_[i]->section_ = &section;
    }
    section.relocations_[i]->architecture_ = this->binary_->header().cpu_type();
    VLOG(VDEBUG) << *section.relocations_.back();;
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
    const uint8_t* raw_rebase = reinterpret_cast<const uint8_t*>(this->stream_->read(offset, size));
    dyldinfo.rebase_opcodes({raw_rebase, raw_rebase + size});
  } catch (const exception& e) {
    LOG(WARNING) << e.what();
  }

  uint64_t current_offset = offset;
  uint64_t end_offset = offset + size;

  bool     done = false;
	uint8_t  type = 0;
	uint32_t segment_index = 0;
	uint64_t segment_offset = 0;
	uint32_t count = 0;
	uint32_t skip = 0;
  std::pair<uint64_t, uint64_t> value_delta = {0, 0};

  while (not done and current_offset < end_offset) {
    uint8_t imm    = this->stream_->read_integer<uint8_t>(current_offset) & REBASE_IMMEDIATE_MASK;
    uint8_t opcode = this->stream_->read_integer<uint8_t>(current_offset) & REBASE_OPCODE_MASK;
    current_offset += sizeof(uint8_t);

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
          value_delta     = this->stream_->read_uleb128(current_offset);

  				segment_index   = imm;
          segment_offset  = std::get<0>(value_delta);

          current_offset += std::get<1>(value_delta);

		  		break;
        }

			case REBASE_OPCODES::REBASE_OPCODE_ADD_ADDR_ULEB:
        {
          value_delta     = this->stream_->read_uleb128(current_offset);

          segment_offset += std::get<0>(value_delta);

          current_offset += std::get<1>(value_delta);
	  			break;
        }

			case REBASE_OPCODES::REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
        {
				  segment_offset += (imm * sizeof(pint_t));
				  break;
        }

			case REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_IMM_TIMES:
        {
          for (size_t i = 0; i < imm; ++i) {
            this->do_rebase<MACHO_T>(type, segment_index, segment_offset);
				    segment_offset += sizeof(pint_t);
				  }
				  break;
        }
			case REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
        {

          value_delta     = this->stream_->read_uleb128(current_offset);

          count           = std::get<0>(value_delta);

          current_offset += std::get<1>(value_delta);

				  for (size_t i = 0; i < count; ++i) {
            this->do_rebase<MACHO_T>(type, segment_index, segment_offset);
					  segment_offset += sizeof(pint_t);
				  }
				  break;
        }

			case REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
        {

          this->do_rebase<MACHO_T>(type, segment_index, segment_offset);

          value_delta     = this->stream_->read_uleb128(current_offset);

          segment_offset += std::get<0>(value_delta) + sizeof(pint_t);

          current_offset += std::get<1>(value_delta);
				  break;
        }

			case REBASE_OPCODES::REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
        {
          // Count
          value_delta     = this->stream_->read_uleb128(current_offset);

          count          += std::get<0>(value_delta);

          current_offset += std::get<1>(value_delta);

          // Skip
          value_delta     = this->stream_->read_uleb128(current_offset);

          skip           += std::get<0>(value_delta);

          current_offset += std::get<1>(value_delta);

				  for (size_t i = 0; i < count; ++i) {
            this->do_rebase<MACHO_T>(type, segment_index, segment_offset);
					  segment_offset += skip + sizeof(pint_t);
				  }

				  break;
        }

			default:
        {
          LOG(ERROR) << "Unsupported opcode: 0x" << std::hex << static_cast<uint32_t>(opcode);
          break;
        }
    }
  }

  it_segments segments = this->binary_->segments();
  // Tie segments and relocations
  // The **OWNER**: Segment (destructor)
  for (SegmentCommand& segment : segments) {
    for (Relocation& relocation : segment.relocations()) {
      relocation.segment_ = &segment;
    }
  }

  // Tie sections and relocations
  for (SegmentCommand& segment : segments) {
    uint64_t offset = 0;

    for (Relocation& relocation : segment.relocations()) {
      try {
        offset = this->binary_->virtual_address_to_offset(relocation.address());
        Section& section = this->binary_->section_from_offset(offset);
        relocation.section_ = &section;
      } catch (const not_found& e) {
        VLOG(VDEBUG) << "Unable to tie a section with dyld relocation at 0x" << std::hex << relocation.address() << " - 0x" << offset;
      }
    }
  }


  // Tie symbols and relocations
  for (Relocation& relocation : this->binary_->relocations()) {
    uint64_t address = relocation.address();
    auto&& it_symbol = std::find_if(
        std::begin(this->binary_->symbols_),
        std::end(this->binary_->symbols_),
        [&address] (const Symbol* sym) {
          return sym->value() == address;
        });

    if (it_symbol != std::end(this->binary_->symbols_)) {
      relocation.symbol_ = *it_symbol;
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
    const uint8_t* raw_binding = reinterpret_cast<const uint8_t*>(this->stream_->read(offset, size));
    dyldinfo.bind_opcodes({raw_binding, raw_binding + size});
  } catch (const exception& e) {
    LOG(WARNING) << e.what();
  }

  uint64_t current_offset = offset;
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

  std::pair<uint64_t, uint64_t> value_delta = {0, 0};
  std::pair<int64_t, uint64_t> svalue_delta = {0, 0};

  while (not done and current_offset < end_offset) {
    uint8_t imm    = this->stream_->read_integer<uint8_t>(current_offset) & BIND_IMMEDIATE_MASK;
    uint8_t opcode = this->stream_->read_integer<uint8_t>(current_offset) & BIND_OPCODE_MASK;
    current_offset += sizeof(uint8_t);

		switch (opcode) {
		  case BIND_OPCODE_DONE:
        {
				  done = true;
					break;
        }

      case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        {
				  library_ordinal = imm;
					break;
        }

			case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        {

          value_delta     = this->stream_->read_uleb128(current_offset);
          library_ordinal = std::get<0>(value_delta);
          current_offset += std::get<1>(value_delta);

					break;
        }

			case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
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

      case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        {
				  symbol_name = this->stream_->read_string(current_offset);
          current_offset += symbol_name.size() + 1;

          if ((imm & BIND_SYMBOL_FLAGS_WEAK_IMPORT) != 0) {
						is_weak_import = true;
          } else {
						is_weak_import = false;
          }
					break;
        }

      case BIND_OPCODE_SET_TYPE_IMM:
        {
					type = imm;
					break;
        }

			case BIND_OPCODE_SET_ADDEND_SLEB:
        {
          svalue_delta    = this->stream_->read_sleb128(current_offset);
          addend          = std::get<0>(svalue_delta);
          current_offset += std::get<1>(svalue_delta);
					break;
        }

			case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        {
					segment_idx  = imm;

          value_delta     = this->stream_->read_uleb128(current_offset);
          segment_offset  = std::get<0>(value_delta);
          current_offset += std::get<1>(value_delta);

					break;
        }

			case BIND_OPCODE_ADD_ADDR_ULEB:
        {
          value_delta     = this->stream_->read_uleb128(current_offset);
          segment_offset += std::get<0>(value_delta);
          current_offset += std::get<1>(value_delta);
					break;
        }

      case BIND_OPCODE_DO_BIND:
        {
          this->do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_STANDARD,
              type,
              segment_idx,
              segment_offset,
              symbol_name,
              library_ordinal,
              addend,
              is_weak_import);
					segment_offset += sizeof(pint_t);
					break;
        }

      case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        {
          this->do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_STANDARD,
              type,
              segment_idx,
              segment_offset,
              symbol_name,
              library_ordinal,
              addend,
              is_weak_import);
          value_delta     = this->stream_->read_uleb128(current_offset);
          segment_offset += std::get<0>(value_delta) + sizeof(pint_t);
          current_offset += std::get<1>(value_delta);
					break;
        }

			case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        {
          this->do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_STANDARD,
              type,
              segment_idx,
              segment_offset,
              symbol_name,
              library_ordinal,
              addend,
              is_weak_import);
          segment_offset += imm * sizeof(pint_t) + sizeof(pint_t);
					break;
        }

      case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
        {

          // Count
          value_delta     = this->stream_->read_uleb128(current_offset);
          count           = std::get<0>(value_delta);
          current_offset += std::get<1>(value_delta);

          // Skip
          value_delta     = this->stream_->read_uleb128(current_offset);
          skip            = std::get<0>(value_delta);
          current_offset += std::get<1>(value_delta);

					for (size_t i = 0; i < count; ++i) {
            this->do_bind<MACHO_T>(
                BINDING_CLASS::BIND_CLASS_STANDARD,
                type,
                segment_idx,
                segment_offset,
                symbol_name,
                library_ordinal,
                addend,
                is_weak_import);
            segment_offset += skip + sizeof(pint_t);
					}
					break;
        }

			default:
        {
          LOG(ERROR) << "Unsupported opcode: 0x" << std::hex << static_cast<uint32_t>(opcode);
          break;
        }
			}
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
    const uint8_t* raw_binding = reinterpret_cast<const uint8_t*>(this->stream_->read(offset, size));
    dyldinfo.weak_bind_opcodes({raw_binding, raw_binding + size});
  } catch (const exception& e) {
    LOG(WARNING) << e.what();
  }

  uint64_t current_offset = offset;
  uint64_t end_offset = offset + size;

	uint8_t     type = 0;
	uint8_t     segment_idx = 0;
	uint64_t    segment_offset = 0;
  std::string symbol_name = "";

	int64_t     addend = 0;
	uint32_t    count = 0;
	uint32_t    skip = 0;

  bool        is_weak_import = true;
	bool        done = false;

  std::pair<uint64_t, uint64_t> value_delta = {0, 0};
  std::pair<int64_t, uint64_t> svalue_delta = {0, 0};

  while (not done and current_offset < end_offset) {
    uint8_t imm    = this->stream_->read_integer<uint8_t>(current_offset) & BIND_IMMEDIATE_MASK;
    uint8_t opcode = this->stream_->read_integer<uint8_t>(current_offset) & BIND_OPCODE_MASK;
    current_offset += sizeof(uint8_t);

		switch (opcode) {
		  case BIND_OPCODE_DONE:
        {
				  done = true;
					break;
        }


      case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        {
				  symbol_name = this->stream_->read_string(current_offset);
          current_offset += symbol_name.size() + 1;

          if ((imm & BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION) != 0) {
            // TODO: STRONG
          }
					break;
        }

      case BIND_OPCODE_SET_TYPE_IMM:
        {
					type = imm;
					break;
        }


			case BIND_OPCODE_SET_ADDEND_SLEB:
        {
          svalue_delta    = this->stream_->read_sleb128(current_offset);
          addend          = std::get<0>(svalue_delta);
          current_offset += std::get<1>(svalue_delta);
					break;
        }


			case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        {
					segment_idx  = imm;

          value_delta     = this->stream_->read_uleb128(current_offset);
          segment_offset  = std::get<0>(value_delta);
          current_offset += std::get<1>(value_delta);

					break;
        }


			case BIND_OPCODE_ADD_ADDR_ULEB:
        {
          value_delta     = this->stream_->read_uleb128(current_offset);
          segment_offset += std::get<0>(value_delta);
          current_offset += std::get<1>(value_delta);
					break;
        }


      case BIND_OPCODE_DO_BIND:
        {
          this->do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_WEAK,
              type,
              segment_idx,
              segment_offset,
              symbol_name,
              0,
              addend,
              is_weak_import);
					segment_offset += sizeof(pint_t);
					break;
        }


      case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        {
          this->do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_WEAK,
              type,
              segment_idx,
              segment_offset,
              symbol_name,
              0,
              addend,
              is_weak_import);
          value_delta     = this->stream_->read_uleb128(current_offset);
          segment_offset += std::get<0>(value_delta) + sizeof(pint_t);
          current_offset += std::get<1>(value_delta);
					break;
        }


			case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        {
          this->do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_WEAK,
              type,
              segment_idx,
              segment_offset,
              symbol_name,
              0,
              addend,
              is_weak_import);
          segment_offset += imm * sizeof(pint_t) + sizeof(pint_t);
					break;
        }


      case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
        {

          // Count
          value_delta     = this->stream_->read_uleb128(current_offset);
          count           = std::get<0>(value_delta);
          current_offset += std::get<1>(value_delta);

          // Skip
          value_delta     = this->stream_->read_uleb128(current_offset);
          skip            = std::get<0>(value_delta);
          current_offset += std::get<1>(value_delta);

					for (size_t i = 0; i < count; ++i) {
            this->do_bind<MACHO_T>(
                BINDING_CLASS::BIND_CLASS_WEAK,
                type,
                segment_idx,
                segment_offset,
                symbol_name,
                0,
                addend,
                is_weak_import);
            segment_offset += skip + sizeof(pint_t);
					}
					break;
        }



			default:
        {
          LOG(ERROR) << "Unsupported opcode: 0x" << std::hex << static_cast<uint32_t>(opcode);
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
    const uint8_t* raw_binding = reinterpret_cast<const uint8_t*>(this->stream_->read(offset, size));
    dyldinfo.lazy_bind_opcodes({raw_binding, raw_binding + size});
  } catch (const exception& e) {
    LOG(WARNING) << e.what();
  }

  uint64_t current_offset = offset;
  uint64_t end_offset     = offset + size;

  uint32_t    lazy_offset     = 0;
	uint8_t     segment_idx     = 0;
	uint64_t    segment_offset  = 0;
  std::string symbol_name     = "";
	int32_t     library_ordinal = 0;
	int64_t     addend          = 0;
  bool        is_weak_import  = false;

  std::pair<uint64_t, uint64_t> value_delta  = {0, 0};
  std::pair< int64_t, uint64_t> svalue_delta = {0, 0};

  while (current_offset < end_offset) {
    uint8_t imm    = this->stream_->read_integer<uint8_t>(current_offset) & BIND_IMMEDIATE_MASK;
    uint8_t opcode = this->stream_->read_integer<uint8_t>(current_offset) & BIND_OPCODE_MASK;
    current_offset += sizeof(uint8_t);

		switch (opcode) {
		  case BIND_OPCODE_DONE:
        {
				  lazy_offset = current_offset - offset;
					break;
        }

      case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        {
				  library_ordinal = imm;
					break;
        }

			case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        {

          value_delta     = this->stream_->read_uleb128(current_offset);
          library_ordinal = std::get<0>(value_delta);
          current_offset += std::get<1>(value_delta);

					break;
        }

			case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
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

      case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        {
				  symbol_name = this->stream_->read_string(current_offset);
          current_offset += symbol_name.size() + 1;

          if ((imm & BIND_SYMBOL_FLAGS_WEAK_IMPORT) != 0) {
						is_weak_import = true;
          } else {
						is_weak_import = false;
          }
					break;
        }

			case BIND_OPCODE_SET_ADDEND_SLEB:
        {
          svalue_delta    = this->stream_->read_sleb128(current_offset);
          addend          = std::get<0>(svalue_delta);
          current_offset += std::get<1>(svalue_delta);
					break;
        }

			case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        {
					segment_idx  = imm;

          value_delta     = this->stream_->read_uleb128(current_offset);
          segment_offset  = std::get<0>(value_delta);
          current_offset += std::get<1>(value_delta);

					break;
        }

      case BIND_OPCODE_DO_BIND:
        {
          this->do_bind<MACHO_T>(
              BINDING_CLASS::BIND_CLASS_LAZY,
              BIND_TYPES::BIND_TYPE_POINTER,
              segment_idx,
              segment_offset,
              symbol_name,
              library_ordinal,
              addend,
              is_weak_import);
					segment_offset += sizeof(pint_t);
					break;
        }

			default:
        {
          LOG(ERROR) << "Unsupported opcode: 0x" << std::hex << static_cast<uint32_t>(opcode);
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
        bool is_weak) {


  using pint_t = typename MACHO_T::uint;

  it_segments segments = this->binary_->segments();
  if (segment_idx >= segments.size()) {
    LOG(ERROR) << "Wrong index (" << std::dec << segment_idx << ")";
    return;
  }
  SegmentCommand& segment = segments[segment_idx];
  // Address to bind
  uint64_t address = segment.virtual_address() + segment_offset;

  // Check if a relocation already exists:
  Relocation* reloc = nullptr;
  bool reloc_exists = false;

  auto&& it_reloc = std::find_if(
      std::begin(segment.relocations_),
      std::end(segment.relocations_),
      [address] (const Relocation* r) {
        return r->address() == address;
      });

  if (it_reloc != std::end(segment.relocations_)) {
    reloc = *it_reloc;
    reloc_exists = true;
  } else {
    reloc = new RelocationDyld{address, type};
  }

  reloc->architecture_ = this->binary_->header().cpu_type();

  switch (static_cast<BIND_TYPES>(type)) {
    case BIND_TYPES::BIND_TYPE_POINTER:
      {
        // *address = value + addend;
        reloc->size_ = sizeof(pint_t) * 8;
        break;
      }

    case BIND_TYPES::BIND_TYPE_TEXT_ABSOLUTE32:
      {

        reloc->size_ = sizeof(uint32_t) * 8;
        // *address = value + addend;
        break;
      }

    case BIND_TYPES::BIND_TYPE_TEXT_PCREL32:
      {

        reloc->size_ = sizeof(uint32_t) * 8;
        //*address = value - (address + 4);
        break;
      }

    default:
      {
        LOG(ERROR) << "Unsuported binding type: 0x" << std::hex << type;
      }
  }

  // Create a BindingInfo object
  BindingInfo* binding_info = new BindingInfo{cls, static_cast<BIND_TYPES>(type), address, addend, ord, is_weak};
  binding_info->segment_ = &segment;


  it_libraries libraries = this->binary_->libraries();
  if (0 < ord and static_cast<size_t>(ord) <= libraries.size()) {
    binding_info->library_ = &libraries[ord - 1];
  }

  try {
    uint64_t offset = this->binary_->virtual_address_to_offset(reloc->address());
    Section& section = this->binary_->section_from_offset(offset);
    reloc->section_ = &section;
  } catch (const not_found&) {
    VLOG(VDEBUG) << "Unable to tie a section with dyld relocation at 0x" << std::hex << reloc->address();
  }

  if (this->binary_->has_symbol(symbol_name)) {
    Symbol& symbol = this->binary_->get_symbol(symbol_name);
    reloc->symbol_ = &symbol;
    //symbol.value(address);
    binding_info->symbol_ = &symbol;
    symbol.binding_info_ = binding_info;
  } else {
    LOG(ERROR) << "New symbol found: " << symbol_name;
  }

  if (not reloc_exists) {
    segment.relocations_.push_back(reloc);
  }
  this->binary_->dyld_info().binding_info_.push_back(binding_info);
  VLOG(VDEBUG) << to_string(cls) << segment.name() << " - " << symbol_name;
}

template<class MACHO_T>
void BinaryParser::do_rebase(uint8_t type, uint8_t segment_idx, uint64_t segment_offset) {
  using pint_t = typename MACHO_T::uint;

  it_segments segments = this->binary_->segments();

  if (segment_idx >= segments.size()) {
    LOG(ERROR) << "Wrong index (" << std::dec << segment_idx << ")";
    return;
  }

  SegmentCommand& segment = segments[segment_idx];
  uint64_t address = segment.virtual_address() + segment_offset;

  // Check if a relocation already exists:
  Relocation* reloc = nullptr;
  bool reloc_exists = false;

  auto&& it_reloc = std::find_if(
      std::begin(segment.relocations_),
      std::end(segment.relocations_),
      [&address] (const Relocation* r) {
        return r->address() == address;
      });

  if (it_reloc != std::end(segment.relocations_)) {
    reloc = *it_reloc;
    reloc_exists = true;
  } else {
    reloc = new RelocationDyld{address, type};
  }

  reloc->architecture_ = this->binary_->header().cpu_type();

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

    default:
      {
        LOG(ERROR) << "Unsuported relocation type: 0x" << std::hex << type;
      }
  }

  if (not reloc_exists) {
    segment.relocations_.push_back(reloc);
  }
};




}
}
