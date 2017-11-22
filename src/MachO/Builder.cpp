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
#include <algorithm>
#include <list>
#include <fstream>
#include <iterator>

#include "LIEF/logging++.hpp"

#include "LIEF/MachO/Builder.hpp"
#include "Builder.tcc"

#include "LIEF/exception.hpp"


namespace LIEF {
namespace MachO {

Builder::~Builder(void) = default;

Builder::Builder(Binary *binary) {
  this->binaries_.push_back(std::move(binary));
  this->binary_ = binary;
  this->build();
}

Builder::Builder(std::vector<Binary*> binaries) {
  this->binaries_ = binaries;
  this->binary_   = this->binaries_.back();
  this->build();
}

void Builder::build(void) {
  if (this->binaries_.size() > 1) {
    throw not_supported("Actually, builder only support single binary");
  }


  this->build_load_commands();
  if (this->binary_->is64_) {
    this->build_segments<MachO64>();
    this->build_symbols<MachO64>();
  } else {
    this->build_segments<MachO32>();
    this->build_symbols<MachO32>();
  }

  this->build_header();
  this->build_uuid();
}


void Builder::build_header(void) {
  VLOG(VDEBUG) << "[+] Building header" << std::endl;
  const Header& binary_header = this->binary_->header();
  if (this->binary_->is64_) {
    mach_header_64 header;
    header.magic      = static_cast<uint32_t>(binary_header.magic());
    header.cputype    = static_cast<uint32_t>(binary_header.cpu_type());
    header.cpusubtype = static_cast<uint32_t>(binary_header.cpu_subtype());
    header.filetype   = static_cast<uint32_t>(binary_header.file_type());
    header.ncmds      = static_cast<uint32_t>(binary_header.nb_cmds());
    header.sizeofcmds = static_cast<uint32_t>(binary_header.sizeof_cmds());
    header.flags      = static_cast<uint32_t>(binary_header.flags());
    header.reserved   = static_cast<uint32_t>(binary_header.reserved());
    std::copy(
      reinterpret_cast<uint8_t*>(&header),
      reinterpret_cast<uint8_t*>(&header) + sizeof(mach_header_64),
      std::begin(this->rawBinary_)
      );
  } else {
    mach_header header;
    header.magic      = static_cast<uint32_t>(binary_header.magic());
    header.cputype    = static_cast<uint32_t>(binary_header.cpu_type());
    header.cpusubtype = static_cast<uint32_t>(binary_header.cpu_subtype());
    header.filetype   = static_cast<uint32_t>(binary_header.file_type());
    header.ncmds      = static_cast<uint32_t>(binary_header.nb_cmds());
    header.sizeofcmds = static_cast<uint32_t>(binary_header.sizeof_cmds());
    header.flags      = static_cast<uint32_t>(binary_header.flags());
    std::copy(
      reinterpret_cast<uint8_t*>(&header),
      reinterpret_cast<uint8_t*>(&header) + sizeof(mach_header),
      std::begin(this->rawBinary_)
      );
  }

}


void Builder::build_load_commands(void) {
  VLOG(VDEBUG) << "[+] Building load segments" << std::endl;

  const auto& binary = this->binaries_.back();
  // Check if the number of segments is correct
  if (binary->header().nb_cmds() != binary->commands_.size()) {
    LOG(WARNING) << "Error: header.nb_cmds = " << std::dec << binary->header().nb_cmds()
                 << " and number of commands is " << binary->commands_.size() << std::endl;
    throw LIEF::builder_error("");
  }

  //uint64_t loadCommandsOffset = this->rawBinary_.size();

  uint64_t segments_size = binary->header().sizeof_cmds();
  if (this->rawBinary_.size() < segments_size) {
    this->rawBinary_.resize(segments_size, 0);
  }

  for (const LoadCommand& command : binary->commands()) {
    auto& data = command.data();
    LOAD_COMMAND_TYPES cmd_type = command.command();
    uint64_t loadCommandsOffset = command.command_offset();
    VLOG(VDEBUG) << "[+] Command offset: 0x" << std::hex << loadCommandsOffset << std::endl;
    switch (cmd_type) {
      //case LOAD_COMMAND_TYPES::LC_SYMTAB:
      //  {
      //    VLOG(VDEBUG) << "\tProcessing Symbols %x", command->command() << std::endl;
      //    auto symbol_command = static_cast<SymbolCommand*>(command);
      //    symtab_command command;

      //    command.cmd     = static_cast<uint32_t>(symbol_command->command());
      //    command.cmdsize = static_cast<uint32_t>(symbol_command->size());
      //    command.symoff  = static_cast<uint32_t>(symbol_command->symbol_offset());
      //    command.nsyms   = static_cast<uint32_t>(symbol_command->numberof_symbols());
      //    command.stroff  = static_cast<uint32_t>(symbol_command->strings_offset());
      //    command.strsize = static_cast<uint32_t>(symbol_command->strings_size());
      //    if (this->rawBinary_.size() < (loadCommandsOffset + data.size())) {
      //      this->rawBinary_.resize(loadCommandsOffset + data.size());
      //    }

      //    std::copy(
      //        reinterpret_cast<uint8_t*>(&command),
      //        reinterpret_cast<uint8_t*>(&command) + sizeof(symtab_command),
      //        std::next(std::begin(this->rawBinary_), loadCommandsOffset)
      //        );

      //    if(binary->is64_) {
      //      uint32_t string_idx = 1;
      //      for (size_t i = 0; i < binary->symbols_.size(); ++i) {
      //        nlist_64 symbol;
      //        auto& binary_symbol = binary->symbols_[i];
      //        if (not binary_symbol->name().empty()) {
      //          const auto& name = binary_symbol->name();
      //          uint32_t name_offset = symbol_command->strings_offset() + string_idx;

      //          if (this->rawBinary_.size() < (name_offset + name.size())) {
      //            this->rawBinary_.resize(name_offset + name.size());
      //          }

      //          std::copy(
      //              std::begin(name),
      //              std::end(name),
      //              std::next(std::begin(this->rawBinary_), name_offset)
      //              );

      //          symbol.n_strx  = string_idx;
      //          string_idx += name.size() + 1;

      //        }
      //        symbol.n_type  = static_cast<uint8_t>(binary_symbol->type());
      //        symbol.n_sect  = static_cast<uint8_t>(binary_symbol->numberof_sections());
      //        symbol.n_desc  = static_cast<uint16_t>(binary_symbol->description());
      //        symbol.n_value = static_cast<uint64_t>(binary_symbol->value());

      //        uint32_t offset = symbol_command->symbol_offset() + i * sizeof(nlist_64);
      //        std::copy(
      //          reinterpret_cast<uint8_t*>(&symbol),
      //          reinterpret_cast<uint8_t*>(&symbol) + sizeof(nlist_64),
      //          std::next(std::begin(this->rawBinary_), offset)
      //        );
      //      }


      //    } else {
      //      throw std::runtime_error("todo");
      //    }
      //    loadCommandsOffset += sizeof(symtab_command);


      //    break;
      //  }

      case LOAD_COMMAND_TYPES::LC_SEGMENT_64:
      case LOAD_COMMAND_TYPES::LC_SEGMENT:
        {
          VLOG(VDEBUG) << "\tProcessing Load command " << to_string(cmd_type) << std::endl;
          if (this->rawBinary_.size() < (loadCommandsOffset + data.size())) {
            this->rawBinary_.resize(loadCommandsOffset + data.size());
          }

          std::copy(
              std::begin(data),
              std::end(data),
              this->rawBinary_.data() + loadCommandsOffset);

          const SegmentCommand& segment = static_cast<const SegmentCommand&>(command);
          auto segment_content = segment.content();

          if (this->rawBinary_.size() < (segment.file_offset() + segment_content.size())) {
            this->rawBinary_.resize(segment.file_offset() + segment_content.size());
          }

          std::copy(
              std::begin(segment_content),
              std::end(segment_content),
              this->rawBinary_.data() + segment.file_offset());

          break;

        }

      default:
        {
          if (this->rawBinary_.size() < (loadCommandsOffset + data.size())) {
            this->rawBinary_.resize(loadCommandsOffset + data.size(), 0);
          }

          std::copy(
              std::begin(data),
              std::end(data),
              this->rawBinary_.data() + loadCommandsOffset);

        }
    }
  }
}

void Builder::build_uuid(void) {
}


const std::vector<uint8_t>& Builder::get_build(void) {
  return this->rawBinary_;
}


void Builder::write(MachO::Binary *binary, const std::string& filename) {
  Builder builder{binary};
  builder.write(filename);
}

void Builder::write(const std::string& filename) const {

  std::ofstream outputFile{filename, std::ios::out | std::ios::binary | std::ios::trunc};
  std::copy(
      std::begin(this->rawBinary_),
      std::end(this->rawBinary_),
      std::ostreambuf_iterator<char>(outputFile));
  outputFile.close();

}

}
}
