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
#include "LIEF/logging++.hpp"

namespace LIEF {
namespace MachO {


template<typename T>
void Builder::build_segments(void) {
  using section_t  = typename T::section;
  using segment_t  = typename T::segment_command;
  using uint__     = typename T::uint;

  LOG(DEBUG) << "[+] Rebuilding segments" << std::endl;
  Binary* binary =  this->binaries_.back();
  for (const SegmentCommand& segment : binary->segments()) {
    LOG(DEBUG) << segment << std::endl;
    segment_t segment_header;
    segment_header.cmd      = static_cast<uint32_t>(segment.command());
    segment_header.cmdsize  = static_cast<uint32_t>(segment.size());
    std::copy(
        segment.name().c_str(),
        segment.name().c_str() + sizeof(segment_header.segname),
        segment_header.segname);
    segment_header.vmaddr   = static_cast<uint__>(segment.virtual_address());
    segment_header.vmsize   = static_cast<uint__>(segment.virtual_size());
    segment_header.fileoff  = static_cast<uint__>(segment.file_offset());
    segment_header.filesize = static_cast<uint__>(segment.file_size());
    segment_header.maxprot  = static_cast<uint32_t>(segment.max_protection());
    segment_header.initprot = static_cast<uint32_t>(segment.init_protection());
    segment_header.nsects   = static_cast<uint32_t>(segment.numberof_sections());
    segment_header.flags    = static_cast<uint32_t>(segment.flags());
    LOG(DEBUG) << "[+] Command offset: " << std::hex << segment.command_offset() << std::endl;

    const auto& content = segment.content();
    if (content.size() != segment.file_size()) {
      throw LIEF::builder_error("content.size() != segment.file_size()");
    }
    std::copy(
        std::begin(content),
        std::end(content),
        this->rawBinary_.data() + segment.file_offset());

    std::copy(
        reinterpret_cast<uint8_t*>(&segment_header),
        reinterpret_cast<uint8_t*>(&segment_header) + sizeof(segment_t),
        this->rawBinary_.data() + segment.command_offset());



    // --------
    // Sections
    // --------
    if (segment.sections().size() != segment.numberof_sections()) {
      throw LIEF::builder_error("segment.sections().size() != segment.numberof_sections()");
    }

    it_const_sections sections = segment.sections();
    for (uint32_t i = 0; i < segment.numberof_sections(); ++i) {
      const Section& section = sections[i];
      LOG(DEBUG) << section << std::endl;
      section_t header;
      std::copy(
          section.name().c_str(),
          section.name().c_str() + sizeof(header.sectname),
          header.sectname);

      std::copy(
          segment.name().c_str(),
          segment.name().c_str() + sizeof(header.segname),
          header.segname);

      header.addr      = static_cast<uint__>(section.address());
      header.size      = static_cast<uint__>(section.size());
      header.offset    = static_cast<uint32_t>(section.offset());
      header.align     = static_cast<uint32_t>(section.alignment());
      header.reloff    = static_cast<uint32_t>(section.relocation_offset());
      header.nreloc    = static_cast<uint32_t>(section.numberof_relocations());
      header.flags     = static_cast<uint32_t>(section.raw_flags());
      header.reserved1 = static_cast<uint32_t>(section.reserved1());
      header.reserved2 = static_cast<uint32_t>(section.reserved2());
      if (std::is_same<section_t, section_64>::value) {
        //header.reserved3 = static_cast<uint32_t>(section.reserved3());
      }
      uint64_t section_header_offset =
        segment.command_offset() +
        sizeof(segment_t) +
        i * sizeof(section_t);
      std::copy(
          reinterpret_cast<uint8_t*>(&header),
          reinterpret_cast<uint8_t*>(&header) + sizeof(section_t),
          this->rawBinary_.data() + section_header_offset);
    }
  }
} // build_segment


template<typename T>
void Builder::build_symbols(void) {
  using nlist_t  = typename T::nlist;

  auto itSymbolCommand = std::find_if(
        std::begin(this->binary_->commands_),
        std::end(this->binary_->commands_),
        [] (const LoadCommand* command) {
          return command->command() == LOAD_COMMAND_TYPES::LC_SYMTAB;
        });
  if (itSymbolCommand == std::end(this->binary_->commands_)) {
    LOG(DEBUG) << "[-] No symbols" << std::endl;
    return;
  }

  LOG(DEBUG) << "[+] Building symbols" << std::endl;
  const SymbolCommand* symbol_command = static_cast<const SymbolCommand*>(*itSymbolCommand);
  symtab_command command;

  command.cmd     = static_cast<uint32_t>(symbol_command->command());
  command.cmdsize = static_cast<uint32_t>(symbol_command->size());
  command.symoff  = static_cast<uint32_t>(symbol_command->symbol_offset());
  command.nsyms   = static_cast<uint32_t>(symbol_command->numberof_symbols());
  command.stroff  = static_cast<uint32_t>(symbol_command->strings_offset());
  command.strsize = static_cast<uint32_t>(symbol_command->strings_size());

  uint64_t loadCommandsOffset = symbol_command->command_offset();

  std::copy(
      reinterpret_cast<uint8_t*>(&command),
      reinterpret_cast<uint8_t*>(&command) + sizeof(symtab_command),
      this->rawBinary_.data() + loadCommandsOffset);

  uint32_t string_idx = 1;
  for (size_t i = 0; i < this->binary_->symbols_.size(); ++i) {
    nlist_t symbol;
    const auto& binary_symbol = this->binary_->symbols_[i];
    if (not binary_symbol->name().empty()) {
      const std::string& name = binary_symbol->name();
      const uint32_t name_offset = symbol_command->strings_offset() + string_idx;

      std::copy(
          std::begin(name),
          std::end(name),
          this->rawBinary_.data() + name_offset);

      this->rawBinary_[name_offset + name.size()] = 0;
      symbol.n_strx  = string_idx;
      string_idx += name.size() + 1;
    }

    symbol.n_type  = static_cast<uint8_t>(binary_symbol->type());
    symbol.n_sect  = static_cast<uint8_t>(binary_symbol->numberof_sections());
    if (std::is_same<T, MachO32>::value) {
      symbol.n_desc = static_cast<uint16_t>(binary_symbol->description());
    } else {
      symbol.n_desc = static_cast<int16_t>(binary_symbol->description());
    }
    symbol.n_value = static_cast<uint32_t>(binary_symbol->value());
    const uint32_t offset = static_cast<uint32_t>(symbol_command->symbol_offset() + i * sizeof(nlist_t));

    std::copy(
      reinterpret_cast<uint8_t*>(&symbol),
      reinterpret_cast<uint8_t*>(&symbol) + sizeof(nlist_t),
      this->rawBinary_.data() + offset);
  }
} // build_symbols
}
}
