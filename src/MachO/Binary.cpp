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
#include "LIEF/utils.hpp"
#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/Builder.hpp"
#include "Object.tcc"
#include "Binary.tcc"

#include "LIEF/MachO/hash.hpp"

#include "LIEF/exception.hpp"

#include <algorithm>
#include <numeric>
#include <sstream>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#else
#define getpagesize() 0x1000
#endif

namespace LIEF {
namespace MachO {

Binary::Binary(void) = default;

LIEF::sections_t Binary::get_abstract_sections(void) {
  LIEF::sections_t result;
  it_sections sections = this->sections();
  std::transform(
      std::begin(sections),
      std::end(sections),
      std::back_inserter(result),
      [] (Section& s) {
       return &s;
      });

  return result;
}
// LIEF Interface
// ==============

void Binary::patch_address(uint64_t address, const std::vector<uint8_t>& patch_value, LIEF::Binary::VA_TYPES) {
  // Find the segment associated with the virtual address
  SegmentCommand* segment_topatch = this->segment_from_virtual_address(address);
  if (segment_topatch == nullptr) {
    LOG(ERROR) << "Unable to find segment associated with address: " << std::hex << std::showbase << address;
    return;
  }
  const uint64_t offset = address - segment_topatch->virtual_address();
  std::vector<uint8_t> content = segment_topatch->content();
  std::copy(
      std::begin(patch_value),
      std::end(patch_value),
      content.data() + offset);
  segment_topatch->content(content);

}

void Binary::patch_address(uint64_t address, uint64_t patch_value, size_t size, LIEF::Binary::VA_TYPES) {
  if (size > sizeof(patch_value)) {
    LOG(ERROR) << "Invalid size: " << std::hex << std::showbase << size;
    return;
  }

  SegmentCommand* segment_topatch = this->segment_from_virtual_address(address);

  if (segment_topatch == nullptr) {
    LOG(ERROR) << "Unable to find segment associated with address: " << std::hex << std::showbase << address;
    return;
  }
  const uint64_t offset = address - segment_topatch->virtual_address();
  std::vector<uint8_t> content = segment_topatch->content();

  std::copy(
      reinterpret_cast<uint8_t*>(&patch_value),
      reinterpret_cast<uint8_t*>(&patch_value) + size,
      content.data() + offset);
  segment_topatch->content(content);

}

std::vector<uint8_t> Binary::get_content_from_virtual_address(uint64_t virtual_address, uint64_t size, LIEF::Binary::VA_TYPES) const {
  const SegmentCommand* segment = this->segment_from_virtual_address(virtual_address);

  if (segment == nullptr) {
    LOG(ERROR) << "Unable to find segment associated with address: " << std::hex << std::showbase << virtual_address;
    return {};
  }

  const std::vector<uint8_t>& content = segment->content();
  const uint64_t offset = virtual_address - segment->virtual_address();

  uint64_t checked_size = size;
  if ((offset + checked_size) > content.size()) {
    checked_size = checked_size - (offset + checked_size - content.size());
  }

  return {content.data() + offset, content.data() + offset + checked_size};
}


uint64_t Binary::entrypoint(void) const {
  if (not this->has_entrypoint()) {
    throw not_found("Entrypoint not found");
  }

  if (this->has_main_command()) {
    return this->imagebase() + this->main_command().entrypoint();
  }


  if (this->has_thread_command()) {
    return this->imagebase() + this->thread_command().pc();
  }

  throw not_found("Entrypoint not found");
}

bool Binary::is_pie(void) const {
  return this->header().has(HEADER_FLAGS::MH_PIE);
}


bool Binary::has_nx(void) const {
  if (not this->header().has(HEADER_FLAGS::MH_NO_HEAP_EXECUTION)) {
    LOG(INFO) << "Heap could be executable";
  }
  return not this->header().has(HEADER_FLAGS::MH_ALLOW_STACK_EXECUTION);
}


bool Binary::has_entrypoint(void) const {
  return this->has_main_command() or this->has_thread_command();
}

LIEF::symbols_t Binary::get_abstract_symbols(void) {
  return {std::begin(this->symbols_), std::end(this->symbols_)};
}


LIEF::Binary::functions_t Binary::get_abstract_exported_functions(void) const {
  LIEF::Binary::functions_t result;
  it_const_exported_symbols syms = this->exported_symbols();
  std::transform(
      std::begin(syms),
      std::end(syms),
      std::back_inserter(result),
      [] (const Symbol& s) {
        return Function{s.name(), s.value(), Function::flags_list_t{Function::FLAGS::EXPORTED}};
      });
  return result;
}

LIEF::Binary::functions_t Binary::get_abstract_imported_functions(void) const {
  LIEF::Binary::functions_t result;
  it_const_imported_symbols syms = this->imported_symbols();
  std::transform(
      std::begin(syms),
      std::end(syms),
      std::back_inserter(result),
      [] (const Symbol& s) {
        return Function{s.name(), s.value(), Function::flags_list_t{Function::FLAGS::IMPORTED}};
      });
  return result;
}


std::vector<std::string> Binary::get_abstract_imported_libraries(void) const {
  std::vector<std::string> result;
  for (const DylibCommand& lib : this->libraries()) {
    result.push_back(lib.name());
  }
  return result;
}


const Header& Binary::header(void) const {
  return this->header_;
}

Header& Binary::header(void) {
  return const_cast<Header&>(static_cast<const Binary*>(this)->header());
}

// Commands
// ========

it_commands Binary::commands(void) {
  return this->commands_;
}

it_const_commands Binary::commands(void) const {
  return it_const_commands{std::cref(this->commands_)};
}

// Symbols
// =======

it_symbols Binary::symbols(void) {
  return this->symbols_;
}

it_const_symbols Binary::symbols(void) const {
  return this->symbols_;
}

it_libraries Binary::libraries(void) {
  libraries_t result;

  for (LoadCommand* library: this->commands_) {
    if (typeid(*library) == typeid(DylibCommand)) {
      result.push_back(dynamic_cast<DylibCommand*>(library));
    }
  }
  return result;
}

it_const_libraries Binary::libraries(void) const {

  libraries_t result;

  for (LoadCommand* library: this->commands_) {
    if (typeid(*library) == typeid(DylibCommand)) {
      result.push_back(dynamic_cast<DylibCommand*>(library));
    }
  }
  return result;
}

it_segments Binary::segments(void) {
  segments_t result{};
  result.reserve(this->commands_.size());
  for (LoadCommand* cmd: this->commands_) {
    if (typeid(*cmd) == typeid(SegmentCommand)) {
      result.push_back(dynamic_cast<SegmentCommand*>(cmd));
    }
  }
  return result;
}

it_const_segments Binary::segments(void) const {
  segments_t result{};
  result.reserve(this->commands_.size());
  for (LoadCommand* cmd: this->commands_) {
    if (typeid(*cmd) == typeid(SegmentCommand)) {
      result.push_back(dynamic_cast<SegmentCommand*>(cmd));
    }
  }
  return result;
}

it_sections Binary::sections(void) {
  sections_t result;
  for (SegmentCommand& segment : this->segments()) {
    for (Section& s: segment.sections()) {
      result.push_back(&s);
    }
  }
  return result;
}

it_const_sections Binary::sections(void) const {
  sections_t result;
  for (const SegmentCommand& segment : this->segments()) {
    for (const Section& s: segment.sections()) {
      result.push_back(const_cast<Section*>(&s));
    }
  }
  return result;
}


// Relocations
it_relocations Binary::relocations() {
  relocations_t result;
  for (SegmentCommand& segment : this->segments()) {
    result.insert(std::begin(segment.relocations_), std::end(segment.relocations_));
  }

  for (Section& section : this->sections()) {
    result.insert(std::begin(section.relocations_), std::end(section.relocations_));
  }

  //if (reload or result.size() != this->relocations_.size()) {
  this->relocations_ = std::move(result);
  //}

  return this->relocations_;
}

it_const_relocations Binary::relocations() const {
  relocations_t result;
  for (const SegmentCommand& segment : this->segments()) {
    result.insert(std::begin(segment.relocations_), std::end(segment.relocations_));
  }

  for (const Section& section : this->sections()) {
    result.insert(std::begin(section.relocations_), std::end(section.relocations_));
  }

  //if (reload or result.size() != this->relocations_.size()) {
  this->relocations_ = std::move(result);
  //}

  return this->relocations_;
}


LIEF::relocations_t Binary::get_abstract_relocations(void) {
  LIEF::relocations_t relocations;
  it_relocations macho_relocations = this->relocations();
  relocations.reserve(macho_relocations.size());

  for (Relocation& r : macho_relocations) {
    relocations.push_back(&r);
  }

  return relocations;
}


// Symbols
// =======

bool Binary::is_exported(const Symbol& symbol) {
  return not symbol.is_external() and symbol.has_export_info();
}

it_exported_symbols Binary::exported_symbols(void) {
  return filter_iterator<symbols_t>{std::ref(this->symbols_),
    [] (const Symbol* symbol) { return is_exported(*symbol); }
  };
}


it_const_exported_symbols Binary::exported_symbols(void) const {
  return const_filter_iterator<symbols_t>{std::cref(this->symbols_),
    [] (const Symbol* symbol) { return is_exported(*symbol); }
  };
}


bool Binary::is_imported(const Symbol& symbol) {
  return symbol.is_external() and not symbol.has_export_info();
}

it_imported_symbols Binary::imported_symbols(void) {
  return filter_iterator<symbols_t>{std::ref(this->symbols_),
    [] (const Symbol* symbol) { return is_imported(*symbol); }
  };
}


it_const_imported_symbols Binary::imported_symbols(void) const {
  return const_filter_iterator<symbols_t>{std::cref(this->symbols_),
    [] (const Symbol* symbol) { return is_imported(*symbol); }
  };
}


bool Binary::has_symbol(const std::string& name) const {
  auto&& it_symbol = std::find_if(
      std::begin(this->symbols_),
      std::end(this->symbols_),
      [&name] (const Symbol* sym) {
        return sym->name() == name;
      });
  return it_symbol != std::end(this->symbols_);
}

const Symbol& Binary::get_symbol(const std::string& name) const {
  if (not this->has_symbol(name)) {
    throw not_found("Unable to find the symbol '" + name + "'");
  }

  auto&& it_symbol = std::find_if(
      std::begin(this->symbols_),
      std::end(this->symbols_),
      [&name] (const Symbol* sym) {
        return sym->name() == name;
      });

  return *(*it_symbol);
}

Symbol& Binary::get_symbol(const std::string& name) {
  return const_cast<Symbol&>(static_cast<const Binary*>(this)->get_symbol(name));
}

// =====


void Binary::write(const std::string& filename) {
  Builder::write(this, filename);
}


const Section* Binary::section_from_offset(uint64_t offset) const {
  it_const_sections sections = this->sections();
  auto&& it_section = std::find_if(
      sections.cbegin(),
      sections.cend(),
      [&offset] (const Section& section) {
        return ((section.offset() <= offset) and
            offset < (section.offset() + section.size()));
      });

  if (it_section == sections.cend()) {
    return nullptr;
  }

  return &(*it_section);
}

Section* Binary::section_from_offset(uint64_t offset) {
  return const_cast<Section*>(static_cast<const Binary*>(this)->section_from_offset(offset));
}


const Section* Binary::section_from_virtual_address(uint64_t address) const {
  it_const_sections sections = this->sections();
  auto&& it_section = std::find_if(
      std::begin(sections),
      std::end(sections),
      [address] (const Section& section) {
        return ((section.virtual_address() <= address) and
            address < (section.virtual_address() + section.size()));
      });

  if (it_section == sections.cend()) {
    return nullptr;
  }

  return &(*it_section);
}

Section* Binary::section_from_virtual_address(uint64_t address) {
  return const_cast<Section*>(static_cast<const Binary*>(this)->section_from_virtual_address(address));
}

const SegmentCommand* Binary::segment_from_virtual_address(uint64_t virtual_address) const {
  it_const_segments segments = this->segments();
  auto&& it_segment = std::find_if(
      std::begin(segments),
      std::end(segments),
      [&virtual_address] (const SegmentCommand& segment) {
        return ((segment.virtual_address() <= virtual_address) and
            virtual_address < (segment.virtual_address() + segment.virtual_size()));
      });

  if (it_segment == segments.cend()) {
    return nullptr;
  }

  return &(*it_segment);
}

size_t Binary::segment_index(const SegmentCommand& segment) const {
  auto&& segments = this->segments();
  auto&& it = std::find_if(
      std::begin(segments),
      std::end(segments),
      [&segment] (const SegmentCommand& s) {
        return s == segment;
      });
  return std::distance(std::begin(segments), it);
}

SegmentCommand* Binary::segment_from_virtual_address(uint64_t virtual_address) {
  return const_cast<SegmentCommand*>(static_cast<const Binary*>(this)->segment_from_virtual_address(virtual_address));
}

const SegmentCommand* Binary::segment_from_offset(uint64_t offset) const {
  it_const_segments segments = this->segments();
  auto&& it_segment = std::find_if(
      std::begin(segments),
      std::end(segments),
      [&offset] (const SegmentCommand& segment) {
        return ((segment.file_offset() <= offset) and
            offset < (segment.file_offset() + segment.file_size()));
      });

  if (it_segment == segments.cend()) {
    return nullptr;
  }

  return &(*it_segment);
}

SegmentCommand* Binary::segment_from_offset(uint64_t offset) {
  return const_cast<SegmentCommand*>(static_cast<const Binary*>(this)->segment_from_offset(offset));
}

void Binary::shift_command(size_t width, size_t from_offset) {
  const SegmentCommand* segment = this->segment_from_offset(from_offset);
  const SegmentCommand* __text_segment = this->get_segment("__TEXT");

  size_t __text_base_addr = 0;
  size_t virtual_address = 0;

  if (segment != nullptr) {
    virtual_address = segment->virtual_address() + from_offset;
  }

  if (__text_segment != nullptr) {
    __text_base_addr = __text_segment->virtual_address();
  }


  // Shift symbols command
  // =====================
  if (this->has_symbol_command()) {
    SymbolCommand& symcmd = this->symbol_command();

    if (symcmd.symbol_offset() > from_offset) {
      symcmd.symbol_offset(symcmd.symbol_offset() + width);
    }

    if (symcmd.strings_offset() > from_offset) {
      symcmd.strings_offset(symcmd.strings_offset() + width);
    }
  }

  // Data In Code
  // ============
  if (this->has_data_in_code()) {
    DataInCode& dcmd = this->data_in_code();

    if (dcmd.data_offset() > from_offset) {
      dcmd.data_offset(dcmd.data_offset() + width);
    }
  }


  // Code Signature
  // ==============
  if (this->has_code_signature()) {
    CodeSignature& sig = this->code_signature();

    if (sig.data_offset() > from_offset) {
      sig.data_offset(sig.data_offset() + width);
    }
  }

  if (this->has_segment_split_info()) {
    SegmentSplitInfo& ssi = this->segment_split_info();

    if (ssi.data_offset() > from_offset) {
      ssi.data_offset(ssi.data_offset() + width);
    }
  }

  // Shift Main Command
  // ==================
  if (this->has_main_command()) {
     if ((__text_base_addr + this->main_command().entrypoint()) > virtual_address) {
      this->main_command().entrypoint(this->main_command().entrypoint() + width);
    }
  }

  // Patch function starts
  // =====================
  if (this->has_function_starts()) {
    FunctionStarts& fs = this->function_starts();
    fs.data_offset(fs.data_offset() + width);
    for (uint64_t& address : this->function_starts().functions()) {
      if ((__text_base_addr + address) > virtual_address) {
        address += width;
      }
    }
  }

  // Dynamic symbol command
  // ======================
  if (this->has_dynamic_symbol_command()) {
    DynamicSymbolCommand& dsymcmd = this->dynamic_symbol_command();
    if (dsymcmd.toc_offset() > from_offset) {
      dsymcmd.toc_offset(dsymcmd.toc_offset() + width);
    }

    if (dsymcmd.module_table_offset() > from_offset) {
      dsymcmd.module_table_offset(dsymcmd.module_table_offset() + width);
    }

    if (dsymcmd.external_reference_symbol_offset() > from_offset) {
      dsymcmd.external_reference_symbol_offset(dsymcmd.external_reference_symbol_offset() + width);
    }

    if (dsymcmd.indirect_symbol_offset() > from_offset) {
      dsymcmd.indirect_symbol_offset(dsymcmd.indirect_symbol_offset() + width);
    }

    if (dsymcmd.external_relocation_offset() > from_offset) {
      dsymcmd.external_relocation_offset(dsymcmd.external_relocation_offset() + width);
    }

    if (dsymcmd.local_relocation_offset() > from_offset) {
      dsymcmd.local_relocation_offset(dsymcmd.local_relocation_offset() + width);
    }
  }

  // Patch Dyld
  // ==========
  if (this->has_dyld_info()) {
    DyldInfo& dyld = this->dyld_info();

    // Shift underlying containers offset
    if (dyld.rebase().first > from_offset) {
      dyld.set_rebase_offset(dyld.rebase().first + width);
    }

    if (dyld.bind().first > from_offset) {
      dyld.set_bind_offset(dyld.bind().first + width);
    }

    if (dyld.weak_bind().first > from_offset) {
      dyld.set_weak_bind_offset(dyld.weak_bind().first + width);
    }

    if (dyld.lazy_bind().first > from_offset) {
      dyld.set_lazy_bind_offset(dyld.lazy_bind().first + width);
    }

    if (dyld.export_info().first > from_offset) {
      dyld.set_export_offset(dyld.export_info().first + width);
    }


    // Shift Relocations
    // -----------------
    // TODO: Optimize this code
    for (Relocation& reloc : this->relocations()) {
      if (reloc.address() > virtual_address) {
        if (this->is64_) {
          this->patch_relocation<uint64_t>(reloc, /* from */ virtual_address, /* shift */ width);
        } else {
          this->patch_relocation<uint32_t>(reloc, /* from */ virtual_address, /* shift */ width);
        }
        reloc.address(reloc.address() + width);
      }
    }

    // Shift Export Info
    // -----------------
    for (ExportInfo& info : dyld.exports()) {
      if (info.address() > virtual_address) {
        info.address(info.address() + width);
      }
    }

    // Shift bindings
    // --------------
    for (BindingInfo& info : dyld.bindings()) {
      if (info.address() > virtual_address) {
        info.address(info.address() + width);
      }
    }
  }


}


void Binary::shift(size_t value) {

  Header& header = this->header();
  const uint64_t loadcommands_start = this->is64_ ? sizeof(mach_header_64) : sizeof(mach_header);
  const uint64_t loadcommands_end   = loadcommands_start + header.sizeof_cmds();

  //header.sizeof_cmds(header.sizeof_cmds() + value);

  // Segment containing load commands
  SegmentCommand* load_cmd_segment = this->segment_from_offset(loadcommands_end);
  CHECK_NE(load_cmd_segment, nullptr);
  std::vector<uint8_t> content = load_cmd_segment->content();

  content.insert(std::begin(content) + loadcommands_end, value, 0);
  load_cmd_segment->content(std::move(content));


  // 1. Shift all commands
  // =====================
  for (LoadCommand* cmd : this->commands_) {
    if (cmd->command_offset() >= loadcommands_end) {
      cmd->command_offset(cmd->command_offset() + value);
    }
  }

  this->shift_command(value, loadcommands_end);

  // Shift Segment and sections
  // ==========================
  for (SegmentCommand& segment : this->segments()) {
    // Extend the virtual size of the segment containing our shift
    if (segment.file_offset() <= loadcommands_end and loadcommands_end < (segment.file_offset() + segment.file_size())) {
      segment.virtual_size(segment.virtual_size() + value);
      segment.file_size(segment.file_size() + value);

      for (Section& section : segment.sections()) {
        if (section.offset() >= loadcommands_end) {
          section.offset(section.offset() + value);
          section.virtual_address(section.virtual_address() + value);
        }
      }
    } else {

      if (segment.file_offset() >= loadcommands_end) {
        segment.file_offset(segment.file_offset() + value);
        segment.virtual_address(segment.virtual_address() + value);
      }

      for (Section& section : segment.sections()) {
        if (section.offset() >= loadcommands_end) {
          section.offset(section.offset() + value);
          section.virtual_address(section.virtual_address() + value);
        }

        if (section.type() == MACHO_SECTION_TYPES::S_ZEROFILL) {
          section.virtual_address(section.virtual_address() + value);
        }
      }
    }
  }

}


LoadCommand& Binary::add(const LoadCommand& command) {
  static constexpr uint32_t shift_value = 0x10000;
  const int32_t size_aligned = align(command.size(), this->pointer_size());

  // Check there is enough spaces between the load command table
  // and the raw content
  if (this->available_command_space_ < size_aligned) {
    this->shift(shift_value);
    this->available_command_space_ += shift_value;
    return this->add(command);
  }

  this->available_command_space_ -= size_aligned;

  Header& header = this->header();

  // Get border of the load command table
  const uint64_t loadcommands_start = this->is64_ ? sizeof(mach_header_64) : sizeof(mach_header);
  const uint64_t loadcommands_end   = loadcommands_start + header.sizeof_cmds();

  // Update the Header according to the command that will be added
  header.sizeof_cmds(header.sizeof_cmds() + size_aligned);
  header.nb_cmds(header.nb_cmds() + 1);

  // Get the segment handling the LC table
  SegmentCommand* load_cmd_segment = this->segment_from_offset(loadcommands_end);
  CHECK_NE(load_cmd_segment, nullptr);

  std::vector<uint8_t> content = load_cmd_segment->content();

  // Copy the command data
  std::copy(
      std::begin(command.data()),
      std::end(command.data()),
      std::begin(content) + loadcommands_end);

  load_cmd_segment->content(std::move(content));

  // Add the command in the Binary
  LoadCommand* copy = command.clone();
  copy->command_offset(loadcommands_end);

  this->commands_.push_back(copy);
  return *this->commands_.back();
}

LoadCommand& Binary::add(const LoadCommand& command, size_t index) {
  static constexpr uint32_t shift_value = 0x10000;

  // If index is "too" large <=> push_back
  if (index >= this->commands_.size()) {
    return this->add(command);
  }

  int32_t size_aligned = align(command.size(), this->pointer_size());

  // Check that we have enough space
  if (this->available_command_space_ < size_aligned) {
    this->shift(shift_value);
    this->available_command_space_ += shift_value;
    return this->add(command, index);
  }

  this->available_command_space_ -= size_aligned;


  // Update the Header according to the new command
  Header& header = this->header();

  header.sizeof_cmds(header.sizeof_cmds() + size_aligned);
  header.nb_cmds(header.nb_cmds() + 1);

  // Get offset of the LC border
  LoadCommand* cmd_border = this->commands_[index];
  size_t border_off = cmd_border->command_offset();

  LoadCommand* copy = command.clone();
  copy->command_offset(cmd_border->command_offset());

  // Patch LC offsets that follow the LC border
  for (LoadCommand* lc : this->commands_) {
    if (lc->command_offset() >= border_off) {
      lc->command_offset(lc->command_offset() + size_aligned);
    }
  }

  this->commands_.insert(std::begin(this->commands_) + index, copy);
  return *copy;
}

bool Binary::remove(const LoadCommand& command) {

  auto&& it = std::find_if(
      std::begin(this->commands_),
      std::end(this->commands_),
      [&command] (const LoadCommand* cmd) {
        return *cmd == command;
      });

  if (it == std::end(this->commands_)) {
    LOG(ERROR) << "Unable to find command: " << command;
    return false;
  }

  LoadCommand* cmd_rm = *it;
  const size_t cmd_rm_offset = cmd_rm->command_offset();
  for (LoadCommand* cmd : this->commands_) {
    if (cmd->command_offset() >= cmd_rm_offset) {
      cmd->command_offset(cmd->command_offset() - cmd_rm->size());
    }
  }


  Header& header = this->header();
  header.sizeof_cmds(header.sizeof_cmds() - cmd_rm->size());
  header.nb_cmds(header.nb_cmds() - 1);
  this->available_command_space_ += cmd_rm->size();

  delete cmd_rm;
  this->commands_.erase(it);

  return true;
}


bool Binary::remove(LOAD_COMMAND_TYPES type) {
  if (not this->has(type)) {
    return false;
  }

  bool done = false;
  while (not done) {
    done = not this->remove(this->get(type));
  }
  return true;
}

bool Binary::remove_command(size_t index) {
  if (index >= this->commands_.size()) {
    return false;
  }
  return this->remove(*this->commands_[index]);
}

bool Binary::has(LOAD_COMMAND_TYPES type) const {
  auto&& it = std::find_if(
      std::begin(this->commands_),
      std::end(this->commands_),
      [type] (const LoadCommand* cmd) {
        return cmd->command() == type;
      });
  return it != std::end(this->commands_);
}

const LoadCommand& Binary::get(LOAD_COMMAND_TYPES type) const {
  if (not this->has(type)) {
    throw not_found(std::string("Can't find '") + to_string(type) + "'");
  }

  auto&& it = std::find_if(
      std::begin(this->commands_),
      std::end(this->commands_),
      [type] (const LoadCommand* cmd) {
        return cmd->command() == type;
      });
  return **it;
}

LoadCommand& Binary::get(LOAD_COMMAND_TYPES type) {
  return const_cast<LoadCommand&>(static_cast<const Binary*>(this)->get(type));
}

bool Binary::extend(const LoadCommand& command, uint64_t size) {
  static constexpr uint32_t shift_value = 0x10000;

  auto&& it = std::find_if(
      std::begin(this->commands_),
      std::end(this->commands_),
      [&command] (const LoadCommand* cmd) {
        return *cmd == command;
      });

  if (it == std::end(this->commands_)) {
    LOG(ERROR) << "Unable to find command: " << command;
    return false;
  }

  LoadCommand* cmd = *it;
  const int32_t size_aligned = align(cmd->size() + size, this->pointer_size());
  const uint32_t extension = size_aligned - cmd->size();
  if (this->available_command_space_ < size_aligned) {
    this->shift(shift_value);
    this->available_command_space_ += shift_value;
    return this->extend(command, size);
  }

  for (LoadCommand* lc : this->commands_) {
    if (lc->command_offset() > cmd->command_offset()) {
      lc->command_offset(lc->command_offset() + extension);
    }
  }

  cmd->size(size_aligned);

  // Update Header
  // =============
  Header& header = this->header();
  header.sizeof_cmds(header.sizeof_cmds() + extension);

  return true;
}


bool Binary::extend_segment(const SegmentCommand& segment, size_t size) {

  auto&& segments = this->segments();
  auto&& it_segment = std::find_if(
      std::begin(segments),
      std::end(segments),
      [&segment] (const SegmentCommand& s) {
        return segment == s;
      });

  if (it_segment == std::end(segments)) {
    LOG(ERROR) << "Unable to find segment: '" << segment.name() << "'";
    return false;
  }

  SegmentCommand& target_segment = *it_segment;
  const size_t last_offset = target_segment.file_offset() + target_segment.file_size();
  const size_t last_va     = target_segment.virtual_address() + target_segment.virtual_size();

  const int32_t size_aligned = align(size, this->pointer_size());

  this->shift_command(size_aligned, last_offset - 4);

  // Shift Segment and sections
  // ==========================
  for (SegmentCommand& segment : this->segments()) {
    if (segment.file_offset() >= last_offset) {
      segment.file_offset(segment.file_offset() + size_aligned);
      segment.virtual_address(segment.virtual_address() + size_aligned);
    }

    for (Section& section : segment.sections()) {
      if (section.offset() >= last_offset) {
        section.offset(section.offset() + size_aligned);
        section.virtual_address(section.virtual_address() + size_aligned);
      }

      if (section.type() == MACHO_SECTION_TYPES::S_ZEROFILL and section.virtual_address() > last_va) {
        section.virtual_address(section.virtual_address() + size_aligned);
      }
    }
  }


  target_segment.virtual_size(target_segment.virtual_size() + size_aligned);
  target_segment.file_size(target_segment.file_size() + size_aligned);
  target_segment.data_.resize(target_segment.file_size());
  return true;
}

void Binary::remove_section(const std::string& name, bool clear) {
  if (not this->has_section(name)) {
    LOG(WARNING) << "Section '" << name << "' not found!";
    return;
  }

  Section& sec_to_delete = this->get_section(name);
  SegmentCommand& segment = sec_to_delete.segment();

  if (clear) {
    sec_to_delete.clear(0);
  }


  segment.numberof_sections(segment.numberof_sections() - 1);
  auto&& it_section = std::find_if(
      std::begin(segment.sections_),
      std::end(segment.sections_),
      [&sec_to_delete] (const Section* s) {
        return *s == sec_to_delete;
      });
  CHECK_NE(it_section, std::end(segment.sections_));

  const size_t lc_offset = segment.command_offset();
  const size_t section_struct_size = this->is64_ ? sizeof(section_64) : sizeof(section_32);
  segment.size_ -= section_struct_size;

  this->header().sizeof_cmds(this->header().sizeof_cmds() - section_struct_size);

  for (LoadCommand* lc : this->commands_) {
    if (lc->command_offset() > lc_offset) {
      lc->command_offset(lc->command_offset() - section_struct_size);
    }
  }

  this->available_command_space_ += section_struct_size;



  delete *it_section;
  segment.sections_.erase(it_section);
}

Section* Binary::add_section(const Section& section) {
  SegmentCommand* __TEXT_segment = this->get_segment("__TEXT");
  if (__TEXT_segment == nullptr) {
    LOG(ERROR) << "Unable to get '__TEXT' segment";
    return nullptr;
  }
  return this->add_section(*__TEXT_segment, section);
}


Section* Binary::add_section(const SegmentCommand& segment, const Section& section) {

  auto&& segments = this->segments();
  auto&& it_segment = std::find_if(
      std::begin(segments),
      std::end(segments),
      [&segment] (const SegmentCommand& s) {
        return segment == s;
      });

  if (it_segment == std::end(segments)) {
    LOG(ERROR) << "Unable to find segment: '" << segment.name() << "'";
    return nullptr;
  }
  SegmentCommand& target_segment = *it_segment;

  const Section::content_t& content = section.content();

  const size_t sec_size = this->is64_ ? sizeof(section_64) : sizeof(section_32);
  const size_t data_size = content.size();
  const int32_t needed_size = align(sec_size + data_size, getpagesize());
  if (this->available_command_space_ < needed_size) {
    this->shift(needed_size);
    this->available_command_space_ += needed_size;
    return this->add_section(segment, section);
  }

  if (not this->extend(target_segment, sec_size)) {
    LOG(ERROR) << "Unable to extend segment '" << segment.name() << "' by "
               << std::hex << std::showbase << sec_size;
    return nullptr;
  }

  this->available_command_space_ -= needed_size;

  Section* new_section = new Section{section};
  // Compute offset, virtual address etc for the new section
  // =======================================================

  // Section raw data will be located just after commands table
  if (section.offset() == 0) {

    uint64_t new_offset = this->is64_ ? sizeof(mach_header_64) : sizeof(mach_header);
    new_offset += this->header().sizeof_cmds();
    new_offset += this->available_command_space_;
    new_section->offset(new_offset);
  }

  if (section.size() == 0) {
    new_section->size(data_size);
  }

  if (section.virtual_address() == 0) {
    new_section->virtual_address(target_segment.virtual_address() + new_section->offset());
  }

  new_section->segment_ = &target_segment;
  target_segment.sections_.push_back(new_section);
  target_segment.numberof_sections(target_segment.numberof_sections() + 1);

  // Copy data to segment
  const size_t relative_offset = new_section->offset() - target_segment.file_offset();

  std::move(
      std::begin(content),
      std::end(content),
      std::begin(target_segment.data_) + relative_offset);

  return new_section;
}


LoadCommand& Binary::add(const SegmentCommand& segment) {
  SegmentCommand new_segment = segment;

  range_t va_ranges  = this->va_ranges();


  if (new_segment.file_size() == 0) {
    const uint64_t new_size = segment.content().size();
    new_segment.file_size(new_size);
  }

  if (new_segment.virtual_size() == 0) {
    const uint64_t new_size = align(new_segment.file_size(), getpagesize());
    new_segment.virtual_size(new_size);
  }

  if (segment.sections().size() > 0) {
    new_segment.nbSections_ = segment.sections().size();
  }

  if (this->is64_) {
    new_segment.command(LOAD_COMMAND_TYPES::LC_SEGMENT_64);
    size_t needed_size = sizeof(segment_command_64);
    needed_size += new_segment.numberof_sections() * sizeof(section_64);
    new_segment.size(needed_size);
  } else {
    new_segment.command(LOAD_COMMAND_TYPES::LC_SEGMENT);
    size_t needed_size = sizeof(segment_command_32);
    needed_size += new_segment.numberof_sections() * sizeof(section_32);
    new_segment.size(needed_size);
  }


  // Insert the segment before __LINKEDIT
  auto&& it_linkedit = std::find_if(
      std::begin(this->commands_),
      std::end(this->commands_),
      [] (const LoadCommand* cmd) {
        if (not cmd->is<SegmentCommand>()) {
          return false;
        }

        const SegmentCommand* sc = cmd->as<SegmentCommand>();
        return sc->name() == "__LINKEDIT";
      });

  size_t pos = std::distance(std::begin(this->commands_), it_linkedit);
  SegmentCommand& segment_added = *this->add(new_segment, pos).as<SegmentCommand>();

  // As virtual address should be shifted after "add" we need to re-update the virtual address after this operation
  range_t new_va_ranges  = this->va_ranges();
  range_t new_off_ranges = this->off_ranges();

  const bool should_patch = (new_va_ranges.second - segment_added.virtual_size()) != va_ranges.second;
  if (segment.virtual_address() == 0 and should_patch) {
    const uint64_t new_va = align(new_va_ranges.second, getpagesize());
    segment_added.virtual_address(new_va);
    size_t current_va = segment_added.virtual_address();
    for (Section& section : segment_added.sections()) {
      section.virtual_address(current_va);
      current_va += section.size();
    }

  }

  if (segment.file_offset() == 0 and should_patch) {
    const uint64_t new_offset = align(new_off_ranges.second, getpagesize());
    segment_added.file_offset(new_offset);
    size_t current_offset = new_offset;
    for (Section& section : segment_added.sections()) {
      section.offset(current_offset);

      current_offset += section.size();
    }
  }

  return segment_added;
}

bool Binary::unexport(const std::string& name) {
  if (not this->has_symbol(name)) {
    return false;
  }
  const Symbol& s = this->get_symbol(name);
  return this->unexport(s);
}

bool Binary::unexport(const Symbol& sym) {
  if (not this->has_dyld_info()) {
    return false;
  }

  DyldInfo& dyld = this->dyld_info();
  auto&& it_export = std::find_if(
      std::begin(dyld.export_info_),
      std::end(dyld.export_info_),
      [&sym] (const ExportInfo* info) {
        return info->has_symbol() and info->symbol() == sym;
      });

  // The symbol is not exported
  if (it_export == std::end(dyld.export_info_)) {
    return false;
  }


  delete *it_export;
  dyld.export_info_.erase(it_export);

  return true;
}

bool Binary::remove(const Symbol& sym) {
  /* bool export_removed = */ this->unexport(sym);

  auto&& it_symbol = std::find_if(
      std::begin(this->symbols_),
      std::end(this->symbols_),
      [&sym] (const Symbol* s) {
        return s->name() == sym.name();
      });

  // No Symbol
  if (it_symbol == std::end(this->symbols_)) {
    return false;
  }

  Symbol* symbol_to_remove = *it_symbol;


  // Remove from the symbol command
  // ------------------------------
  if (this->has_symbol_command()) {
    SymbolCommand& sym_cmd = this->symbol_command();
    if (sym_cmd.numberof_symbols() > 0) {
      sym_cmd.numberof_symbols(sym_cmd.numberof_symbols() - 1);
    }

    size_t size = this->is64_ ? sizeof(nlist_64) : sizeof(nlist_32);
    sym_cmd.strings_offset(sym_cmd.strings_offset() - size);
  }

  // Remove from the dynamic symbol command
  // --------------------------------------
  if (this->has_dynamic_symbol_command()) {
    DynamicSymbolCommand& dynsym_cmd = this->dynamic_symbol_command();
    std::vector<Symbol*> symtab;
    symtab.reserve(this->symbols_.size());
    for (Symbol* s : this->symbols_) {
      if (s->origin() == SYMBOL_ORIGINS::SYM_ORIGIN_LC_SYMTAB) {
        symtab.push_back(s);
      }
    }
    auto&& it_symtab = std::find_if(
        std::begin(symtab),
        std::end(symtab),
        [symbol_to_remove] (const Symbol* symtab_sym) {
          return *symbol_to_remove == *symtab_sym;
        });

    if (it_symtab != std::end(symtab)) {
      size_t idx = std::distance(std::begin(symtab), it_symtab);

      // Update local symbols
      // ====================

      // Check if ``idx`` is included in
      // [idx_local_symbol, idx_local_symbol + nb_local_symbols [
      if (idx >= dynsym_cmd.idx_local_symbol() and idx < (dynsym_cmd.idx_local_symbol() + dynsym_cmd.nb_local_symbols())) {
        dynsym_cmd.nb_local_symbols(dynsym_cmd.nb_local_symbols() - 1);

        if (idx == dynsym_cmd.idx_local_symbol()) {
          dynsym_cmd.idx_local_symbol(dynsym_cmd.idx_local_symbol() + 1);
        }
      }


      // External define symbols
      // =======================
      if (idx >= dynsym_cmd.idx_external_define_symbol() and idx < (dynsym_cmd.idx_external_define_symbol() + dynsym_cmd.nb_external_define_symbols())) {
        dynsym_cmd.nb_external_define_symbols(dynsym_cmd.nb_external_define_symbols() - 1);
        if (idx == dynsym_cmd.idx_external_define_symbol()) {
          dynsym_cmd.idx_external_define_symbol(dynsym_cmd.idx_external_define_symbol() + 1);
        }
      }

      // Undefned symbols
      // ================
      if (idx >= dynsym_cmd.idx_undefined_symbol() and idx < (dynsym_cmd.idx_undefined_symbol() + dynsym_cmd.nb_undefined_symbols())) {
        dynsym_cmd.nb_undefined_symbols(dynsym_cmd.nb_undefined_symbols() - 1);
        if (idx == dynsym_cmd.idx_undefined_symbol()) {
          dynsym_cmd.idx_undefined_symbol(dynsym_cmd.idx_undefined_symbol() + 1);
        }
      }

      if (idx < dynsym_cmd.idx_local_symbol()) {
        dynsym_cmd.idx_local_symbol(dynsym_cmd.idx_local_symbol() - 1);
      }

      if (idx < dynsym_cmd.idx_external_define_symbol()) {
        dynsym_cmd.idx_external_define_symbol(dynsym_cmd.idx_external_define_symbol() - 1);
      }

      if (idx < dynsym_cmd.idx_undefined_symbol()) {
        dynsym_cmd.idx_undefined_symbol(dynsym_cmd.idx_undefined_symbol() - 1);
      }

      //if (dynsym_cmd.nb_indirect_symbols() > 0) {
      //  dynsym_cmd.nb_indirect_symbols(dynsym_cmd.nb_indirect_symbols() - 1);
      //}
      // TODO: WIP
      // ==========================================
      if (dynsym_cmd.nb_indirect_symbols() > 0) {
        size_t size = this->is64_ ? sizeof(nlist_64) : sizeof(nlist_32);
        dynsym_cmd.indirect_symbol_offset( dynsym_cmd.indirect_symbol_offset() - size);
      }

      // ==================================
    }
  }


  // Remove from symbol table
  // ------------------------
  delete symbol_to_remove;
  this->symbols_.erase(it_symbol);
  symbol_to_remove = nullptr;
  return true;
}

bool Binary::remove_symbol(const std::string& name) {
  bool removed = false;
  while (this->has_symbol(name)) {
    const Symbol& s = this->get_symbol(name);
    if (not this->remove(s)) {
      break;
    }

    removed = true;
  }
  return removed;
}


bool Binary::remove_signature(void) {

  if (not this->has_code_signature()) {
    LOG(WARNING) << "No signature found!";
    return false;
  }

  const CodeSignature& cs = this->code_signature();
  return this->remove(cs);
}

LoadCommand& Binary::add(const DylibCommand& library) {
  return this->add(*library.as<LoadCommand>());
}

LoadCommand& Binary::add_library(const std::string& name) {
  return this->add(DylibCommand::load_dylib(name));
}


std::vector<uint8_t> Binary::raw(void) {
  Builder builder{this};
  return builder();
}

uint64_t Binary::virtual_address_to_offset(uint64_t virtual_address) const {
  const SegmentCommand* segment = segment_from_virtual_address(virtual_address);
  if (segment == nullptr) {
    return static_cast<uint64_t>(-1);
  }
  const uint64_t base_address = segment->virtual_address() - segment->file_offset();
  return virtual_address - base_address;
}


bool Binary::disable_pie(void) {
  if (this->is_pie()) {
    this->header().remove(HEADER_FLAGS::MH_PIE);
    return true;
  }
  return false;
}



bool Binary::has_section(const std::string& name) const {
  it_const_sections sections = this->sections();

  auto&& it_section = std::find_if(
      std::begin(sections),
      std::end(sections),
      [&name] (const Section& sec) {
        return sec.name() == name;
      });

  return it_section != sections.cend();
}

Section& Binary::get_section(const std::string& name) {
  return const_cast<Section&>(static_cast<const Binary*>(this)->get_section(name));
}

const Section& Binary::get_section(const std::string& name) const {
  if (not this->has_section(name)) {
    throw not_found("'" + name + "' not found in the binary");
  }
  it_const_sections sections = this->sections();
  auto&& it_section = std::find_if(
      std::begin(sections),
      std::end(sections),
      [&name] (const Section& sec) {
        return sec.name() == name;
      });
  return *it_section;
}


bool Binary::has_segment(const std::string& name) const {
  it_const_segments segments = this->segments();

  auto&& it_segment = std::find_if(
      std::begin(segments),
      std::end(segments),
      [&name] (const SegmentCommand& seg) {
        return seg.name() == name;
      });
  return it_segment != std::end(segments);
}

const SegmentCommand* Binary::get_segment(const std::string& name) const {
  if (not this->has_segment(name)) {
    return nullptr;
  }

  it_const_segments segments = this->segments();
  auto&& it_segment = std::find_if(
      std::begin(segments),
      std::end(segments),
      [&name] (const SegmentCommand& seg) {
        return seg.name() == name;
      });
  return &(*it_segment);
}

SegmentCommand* Binary::get_segment(const std::string& name) {
  return const_cast<SegmentCommand*>(static_cast<const Binary*>(this)->get_segment(name));
}

uint64_t Binary::imagebase(void) const {
  it_const_segments segments = this->segments();
  auto&& it_text_segment = std::find_if(
      std::begin(segments),
      std::end(segments),
      [] (const SegmentCommand& segment) {
        return segment.name() == "__TEXT";
      });

  if (it_text_segment == segments.cend()) {
    return 0;
  }

  return it_text_segment->virtual_address();
}


const std::string& Binary::loader(void) const {
  return this->dylinker().name();
}

uint64_t Binary::fat_offset(void) const {
  return this->fat_offset_;
}


bool Binary::is_valid_addr(uint64_t address) const {
  range_t r = this->va_ranges();
  return address <= r.second and address >= r.first;
}


Binary::range_t Binary::va_ranges(void) const {

  it_const_segments segments = this->segments();
  auto&& it_min = std::min_element(
      std::begin(segments), std::end(segments),
      [] (const SegmentCommand& lhs, const SegmentCommand& rhs) {
        if (lhs.virtual_address() == 0 or rhs.virtual_address() == 0) {
          return true;
        }
        return lhs.virtual_address() < rhs.virtual_address();
      });


  auto&& it_max = std::min_element(
      std::begin(segments), std::end(segments),
      [] (const SegmentCommand& lhs, const SegmentCommand& rhs) {
        return (lhs.virtual_address() + lhs.virtual_size()) > (rhs.virtual_address() + rhs.virtual_size());
      });

  return {it_min->virtual_address(), it_max->virtual_address() + it_max->virtual_size()};
}

Binary::range_t Binary::off_ranges(void) const {

  it_const_segments segments = this->segments();
  auto&& it_min = std::min_element(
      std::begin(segments), std::end(segments),
      [] (const SegmentCommand& lhs, const SegmentCommand& rhs) {
        if (lhs.file_offset() == 0 or rhs.file_offset() == 0) {
          return true;
        }
        return lhs.file_offset() < rhs.file_offset();
      });


  auto&& it_max = std::min_element(
      std::begin(segments), std::end(segments),
      [] (const SegmentCommand& lhs, const SegmentCommand& rhs) {
        return (lhs.file_offset() + lhs.file_size()) > (rhs.file_offset() + rhs.file_size());
      });

  return {it_min->file_offset(), it_max->file_offset() + it_max->file_size()};
}



LIEF::Header Binary::get_abstract_header(void) const {
  LIEF::Header header;
  const std::pair<ARCHITECTURES, std::set<MODES>>& am = this->header().abstract_architecture();
  header.architecture(am.first);
  header.modes(am.second);
  if (this->has_entrypoint()) {
    header.entrypoint(this->entrypoint());
  } else {
    header.entrypoint(0);
  }

  header.object_type(this->header().abstract_object_type());
  header.endianness(this->header().abstract_endianness());

  return header;
}


LIEF::Binary::functions_t Binary::ctor_functions(void) const {
  LIEF::Binary::functions_t functions;
  for (const Section& section : this->sections()) {
    if (section.type() != MACHO_SECTION_TYPES::S_MOD_INIT_FUNC_POINTERS) {
      continue;
    }

    const std::vector<uint8_t>& content = section.content();
    if (this->is64_) {
      const size_t nb_fnc = content.size() / sizeof(uint64_t);
      const uint64_t* aptr = reinterpret_cast<const uint64_t*>(content.data());
      for (size_t i = 0; i < nb_fnc; ++i) {
        functions.emplace_back(
            "ctor_" + std::to_string(i),
            aptr[i],
            Function::flags_list_t{Function::FLAGS::CONSTRUCTOR});
      }

    } else {
      const size_t nb_fnc = content.size() / sizeof(uint32_t);
      const uint32_t* aptr = reinterpret_cast<const uint32_t*>(content.data());
      for (size_t i = 0; i < nb_fnc; ++i) {
        functions.emplace_back(
            "ctor_" + std::to_string(i),
            aptr[i],
            Function::flags_list_t{Function::FLAGS::CONSTRUCTOR});
      }
    }
  }
  return functions;
}


LIEF::Binary::functions_t Binary::functions(void) const {
  static const auto func_cmd = [] (const Function& lhs, const Function& rhs) {
    return lhs.address() < rhs.address();
  };
  std::set<Function, decltype(func_cmd)> functions_set(func_cmd);

  LIEF::Binary::functions_t unwind_functions = this->unwind_functions();
  LIEF::Binary::functions_t ctor_functions   = this->ctor_functions();
  LIEF::Binary::functions_t exported         = this->get_abstract_exported_functions();

  std::move(
      std::begin(unwind_functions),
      std::end(unwind_functions),
      std::inserter(functions_set, std::end(functions_set)));

  std::move(
      std::begin(ctor_functions),
      std::end(ctor_functions),
      std::inserter(functions_set, std::end(functions_set)));


  std::move(
      std::begin(exported),
      std::end(exported),
      std::inserter(functions_set, std::end(functions_set)));

  return {std::begin(functions_set), std::end(functions_set)};

}

LIEF::Binary::functions_t Binary::unwind_functions(void) const {
  static constexpr size_t UNWIND_COMPRESSED = 3;
  static constexpr size_t UNWIND_UNCOMPRESSED = 2;

  // Set container to have functions with unique address
  static const auto fcmd = [] (const Function& l, const Function& r) {
    return l.address() < r.address();
  };
  std::set<Function, decltype(fcmd)> functions(fcmd);

  // Look for the __unwind_info section
  if (not this->has_section("__unwind_info")) {
    return {};
  }
  const Section& unwind_section = this->get_section("__unwind_info");
  const std::vector<uint8_t>& unwind_data = unwind_section.content();
  VectorStream vs{unwind_data};

  if (not vs.can_read<unwind_info_section_header>()) {
    LOG(ERROR) << "Can't read unwind section header!";
    return {};
  }

  // Get section content
  const unwind_info_section_header& hdr = vs.read<unwind_info_section_header>();
  vs.setpos(hdr.index_section_offset);

  size_t lsda_start = -1lu;
  size_t lsda_stop = 0;
  for (size_t i = 0; i < hdr.index_count; ++i) {
    if (not vs.can_read<unwind_info_section_header_index_entry>()) {
      LOG(ERROR) << "Can't read function information at index" << std::dec << i << std::endl;
      break;
    }
    const unwind_info_section_header_index_entry& section_hdr = vs.read<unwind_info_section_header_index_entry>();

    functions.emplace(section_hdr.function_offset);
    const size_t second_lvl_off = section_hdr.second_level_pages_section_offset;
    const size_t lsda_off       = section_hdr.lsda_index_array_section_offset;

    lsda_start = std::min(lsda_off, lsda_start);
    lsda_stop  = std::max(lsda_off, lsda_stop);

    if (second_lvl_off > 0 and vs.can_read<unwind_info_regular_second_level_page_header>(second_lvl_off)) {
      const size_t saved_pos = vs.pos();
      {
        vs.setpos(second_lvl_off);
        const unwind_info_regular_second_level_page_header& lvl_hdr = vs.peek<unwind_info_regular_second_level_page_header>(second_lvl_off);
        if (lvl_hdr.kind == UNWIND_COMPRESSED) {
          const unwind_info_compressed_second_level_page_header& lvl_compressed_hdr = vs.read<unwind_info_compressed_second_level_page_header>();

          vs.setpos(second_lvl_off + lvl_compressed_hdr.entry_page_offset);
          for (size_t j = 0; j < lvl_compressed_hdr.entry_count; ++j) {
            uint32_t entry    = vs.read<uint32_t>();
            uint32_t func_off = section_hdr.function_offset + (entry & 0xffffff);
            functions.emplace(func_off);
          }
        }
        else if (lvl_hdr.kind == UNWIND_UNCOMPRESSED) {
          LOG(WARNING) << "UNWIND_UNCOMPRESSED is not supported yet!";
        }
        else {
          LOG(WARNING) << "Unknown 2nd level kind (" << std::dec << lvl_hdr.kind << ")";
        }
      }
      vs.setpos(saved_pos);
    }

  }

  const size_t nb_lsda = lsda_stop > lsda_start ? (lsda_stop - lsda_start) / sizeof(unwind_info_section_header_lsda_index_entry) : 0;
  vs.setpos(lsda_start);
  for (size_t i = 0; i < nb_lsda; ++i) {
    if (not vs.can_read<unwind_info_section_header_lsda_index_entry>()) {
      LOG(ERROR) << "Can't read LSDA at index " << std::dec << i;
      break;
    }
    const unwind_info_section_header_lsda_index_entry& hdr = vs.read<unwind_info_section_header_lsda_index_entry>();
    functions.emplace(hdr.function_offset);
  }

  return {
    std::begin(functions),
    std::end(functions)
  };
}

// UUID
// ++++
bool Binary::has_uuid(void) const {
  return this->has_command<UUIDCommand>();
}

UUIDCommand& Binary::uuid(void) {
  return this->command<UUIDCommand>();
}

const UUIDCommand& Binary::uuid(void) const {
  return this->command<UUIDCommand>();
}

// MainCommand
// +++++++++++
bool Binary::has_main_command(void) const {
  return this->has_command<MainCommand>();
}

MainCommand& Binary::main_command(void) {
  return this->command<MainCommand>();
}

const MainCommand& Binary::main_command(void) const {
  return this->command<MainCommand>();
}

// DylinkerCommand
// +++++++++++++++
bool Binary::has_dylinker(void) const {
  return this->has_command<DylinkerCommand>();
}

DylinkerCommand& Binary::dylinker(void) {
  return this->command<DylinkerCommand>();
}

const DylinkerCommand& Binary::dylinker(void) const {
  return this->command<DylinkerCommand>();
}

// DyldInfo
// ++++++++
bool Binary::has_dyld_info(void) const {
  return this->has_command<DyldInfo>();
}

DyldInfo& Binary::dyld_info(void) {
  return this->command<DyldInfo>();
}

const DyldInfo& Binary::dyld_info(void) const {
  return this->command<DyldInfo>();
}

// Function Starts
// +++++++++++++++
bool Binary::has_function_starts(void) const {
  return this->has_command<FunctionStarts>();
}

FunctionStarts& Binary::function_starts(void) {
  return this->command<FunctionStarts>();
}

const FunctionStarts& Binary::function_starts(void) const {
  return this->command<FunctionStarts>();
}

// Source Version
// ++++++++++++++
bool Binary::has_source_version(void) const {
  return this->has_command<SourceVersion>();
}

SourceVersion& Binary::source_version(void) {
  return this->command<SourceVersion>();
}

const SourceVersion& Binary::source_version(void) const {
  return this->command<SourceVersion>();
}

// Version Min
// +++++++++++
bool Binary::has_version_min(void) const {
  return this->has_command<VersionMin>();
}

VersionMin& Binary::version_min(void) {
  return this->command<VersionMin>();
}

const VersionMin& Binary::version_min(void) const {
  return this->command<VersionMin>();
}



// Thread command
// ++++++++++++++
bool Binary::has_thread_command(void) const {
  return this->has_command<ThreadCommand>();
}

ThreadCommand& Binary::thread_command(void) {
  return this->command<ThreadCommand>();
}

const ThreadCommand& Binary::thread_command(void) const {
  return this->command<ThreadCommand>();
}

// RPath command
// +++++++++++++
bool Binary::has_rpath(void) const {
  return this->has_command<RPathCommand>();
}

RPathCommand& Binary::rpath(void) {
  return this->command<RPathCommand>();
}

const RPathCommand& Binary::rpath(void) const {
  return this->command<RPathCommand>();
}

// SymbolCommand command
// +++++++++++++++++++++
bool Binary::has_symbol_command(void) const {
  return this->has_command<SymbolCommand>();
}

SymbolCommand& Binary::symbol_command(void) {
  return this->command<SymbolCommand>();
}

const SymbolCommand& Binary::symbol_command(void) const {
  return this->command<SymbolCommand>();
}

// DynamicSymbolCommand command
// ++++++++++++++++++++++++++++
bool Binary::has_dynamic_symbol_command(void) const {
  return this->has_command<DynamicSymbolCommand>();
}

DynamicSymbolCommand& Binary::dynamic_symbol_command(void) {
  return this->command<DynamicSymbolCommand>();
}

const DynamicSymbolCommand& Binary::dynamic_symbol_command(void) const {
  return this->command<DynamicSymbolCommand>();
}

// CodeSignature command
// +++++++++++++++++++++
bool Binary::has_code_signature(void) const {
  return this->has_command<CodeSignature>();
}

CodeSignature& Binary::code_signature(void) {
  return this->command<CodeSignature>();
}

const CodeSignature& Binary::code_signature(void) const {
  return this->command<CodeSignature>();
}


// DataInCode command
// ++++++++++++++++++
bool Binary::has_data_in_code(void) const {
  return this->has_command<DataInCode>();
}

DataInCode& Binary::data_in_code(void) {
  return this->command<DataInCode>();
}

const DataInCode& Binary::data_in_code(void) const {
  return this->command<DataInCode>();
}


// SegmentSplitInfo command
// ++++++++++++++++++++++++
bool Binary::has_segment_split_info(void) const {
  return this->has_command<SegmentSplitInfo>();
}

SegmentSplitInfo& Binary::segment_split_info(void) {
  return this->command<SegmentSplitInfo>();
}

const SegmentSplitInfo& Binary::segment_split_info(void) const {
  return this->command<SegmentSplitInfo>();
}


// SubFramework command
// ++++++++++++++++++++
bool Binary::has_sub_framework(void) const {
  return this->has_command<SubFramework>();
}

SubFramework& Binary::sub_framework(void) {
  return this->command<SubFramework>();
}

const SubFramework& Binary::sub_framework(void) const {
  return this->command<SubFramework>();
}

// DyldEnvironment command
// +++++++++++++++++++++++
bool Binary::has_dyld_environment(void) const {
  return this->has_command<DyldEnvironment>();
}

DyldEnvironment& Binary::dyld_environment(void) {
  return this->command<DyldEnvironment>();
}

const DyldEnvironment& Binary::dyld_environment(void) const {
  return this->command<DyldEnvironment>();
}

// EncryptionInfo command
// +++++++++++++++++++++++
bool Binary::has_encryption_info(void) const {
  return this->has_command<EncryptionInfo>();
}

EncryptionInfo& Binary::encryption_info(void) {
  return this->command<EncryptionInfo>();
}

const EncryptionInfo& Binary::encryption_info(void) const {
  return this->command<EncryptionInfo>();
}


// BuildVersion command
// ++++++++++++++++++++
bool Binary::has_build_version(void) const {
  return this->has_command<BuildVersion>();
}

BuildVersion& Binary::build_version(void) {
  return this->command<BuildVersion>();
}

const BuildVersion& Binary::build_version(void) const {
  return this->command<BuildVersion>();
}


LoadCommand& Binary::operator[](LOAD_COMMAND_TYPES type) {
  return this->get(type);
}

const LoadCommand& Binary::operator[](LOAD_COMMAND_TYPES type) const {
  return this->get(type);
}


void Binary::accept(LIEF::Visitor& visitor) const {
  visitor.visit(*this);
}


Binary::~Binary(void) {
  for (LoadCommand *cmd : this->commands_) {
    delete cmd;
  }

  for (Symbol *symbol : this->symbols_) {
    delete symbol;
  }

}


std::ostream& Binary::print(std::ostream& os) const {
  os << "Header" << std::endl;
  os << "======" << std::endl;

  os << this->header();
  os << std::endl;


  os << "Commands" << std::endl;
  os << "========" << std::endl;
  for (const LoadCommand& cmd : this->commands()) {
    os << cmd << std::endl;
  }

  os << std::endl;

  os << "Sections" << std::endl;
  os << "========" << std::endl;
  for (const Section& section : this->sections()) {
    os << section << std::endl;
  }

  os << std::endl;

  os << "Symbols" << std::endl;
  os << "=======" << std::endl;
  for (const Symbol& symbol : this->symbols()) {
    os << symbol << std::endl;
  }

  os << std::endl;
  return os;
}

}
}

