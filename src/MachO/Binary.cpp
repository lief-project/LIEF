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

#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/Builder.hpp"
#include "Binary.tcc"

#include "LIEF/exception.hpp"

#include <algorithm>
#include <numeric>

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

void Binary::patch_address(uint64_t address, const std::vector<uint8_t>& patch_value) {
  // Find the segment associated with the virtual address
  SegmentCommand& segment_topatch = this->segment_from_virtual_address(address);
  const uint64_t offset = address - segment_topatch.virtual_address();
  std::vector<uint8_t> content = segment_topatch.content();
  std::copy(
      std::begin(patch_value),
      std::end(patch_value),
      content.data() + offset);
  segment_topatch.content(content);

}

void Binary::patch_address(uint64_t address, uint64_t patch_value, size_t size) {
  if (size > sizeof(patch_value)) {
    throw std::runtime_error("Invalid size (" + std::to_string(size) + ")");
  }

  SegmentCommand& segment_topatch = this->segment_from_virtual_address(address);
  const uint64_t offset = address - segment_topatch.virtual_address();
  std::vector<uint8_t> content = segment_topatch.content();

  std::copy(
      reinterpret_cast<uint8_t*>(&patch_value),
      reinterpret_cast<uint8_t*>(&patch_value) + size,
      content.data() + offset);
  segment_topatch.content(content);

}

std::vector<uint8_t> Binary::get_content_from_virtual_address(uint64_t virtual_address, uint64_t size) const {
  const SegmentCommand& segment = this->segment_from_virtual_address(virtual_address);
  const std::vector<uint8_t>& content = segment.content();
  const uint64_t offset = virtual_address - segment.virtual_address();
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

  // TODO: LC_THREAD
  auto&& it_main_command = std::find_if(
      std::begin(this->commands_),
      std::end(this->commands_),
      [] (const LoadCommand* command) {
        return command != nullptr and command->command() == LOAD_COMMAND_TYPES::LC_MAIN;
      });

  const MainCommand* main_command = dynamic_cast<const MainCommand*>(*it_main_command);

  return this->imagebase() + main_command->entrypoint();
}


bool Binary::has_entrypoint(void) const {
  auto&& it_main_command = std::find_if(
      std::begin(this->commands_),
      std::end(this->commands_),
      [] (const LoadCommand* command) {
        return command != nullptr and command->command() == LOAD_COMMAND_TYPES::LC_MAIN;
      });

  return it_main_command != std::end(this->commands_);
}

LIEF::symbols_t Binary::get_abstract_symbols(void) {
  return {std::begin(this->symbols_), std::end(this->symbols_)};
}


std::vector<std::string> Binary::get_abstract_exported_functions(void) const {
  std::vector<std::string> result;
  it_const_exported_symbols syms = this->get_exported_symbols();
  std::transform(
      std::begin(syms),
      std::end(syms),
      std::back_inserter(result),
      [] (const Symbol& s) {
        return s.name();
      });
  return result;
}

std::vector<std::string> Binary::get_abstract_imported_functions(void) const {
  std::vector<std::string> result;
  it_const_imported_symbols syms = this->get_imported_symbols();
  std::transform(
      std::begin(syms),
      std::end(syms),
      std::back_inserter(result),
      [] (const Symbol& s) {
      return s.name();
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
  return it_commands{std::ref(this->commands_)};
}

it_const_commands Binary::commands(void) const {
  return it_const_commands{std::cref(this->commands_)};
}

// Symbols
// =======

it_symbols Binary::symbols(void) {
  return it_symbols{std::ref(this->symbols_)};
}

it_const_symbols Binary::symbols(void) const {
  return it_const_symbols{std::cref(this->symbols_)};
}

it_libraries Binary::libraries(void) {
  libraries_t result;

  for (LoadCommand* library: this->commands_) {
    if (dynamic_cast<DylibCommand*>(library)) {
      result.push_back(dynamic_cast<DylibCommand*>(library));
    }
  }
  return it_libraries{result};
}

it_const_libraries Binary::libraries(void) const {

  libraries_t result;

  for (LoadCommand* library: this->commands_) {
    if (dynamic_cast<DylibCommand*>(library)) {
      result.push_back(dynamic_cast<DylibCommand*>(library));
    }
  }
  return it_const_libraries{result};
}

it_segments Binary::segments(void) {
  segments_t result{};

  for (LoadCommand* cmd: this->commands_) {
    if (dynamic_cast<SegmentCommand*>(cmd)) {
      result.push_back(dynamic_cast<SegmentCommand*>(cmd));
    }
  }
  return it_segments{result};
}

it_const_segments Binary::segments(void) const {
  segments_t result{};

  for (LoadCommand* cmd: this->commands_) {
    if (dynamic_cast<SegmentCommand*>(cmd)) {
      result.push_back(dynamic_cast<SegmentCommand*>(cmd));
    }
  }
  return it_const_segments{result};
}

it_sections Binary::sections(void) {
  sections_t result;
  for (SegmentCommand& segment : this->segments()) {
    for (Section& s: segment.sections()) {
      result.push_back(&s);
    }
  }
  return it_sections{result};
}

it_const_sections Binary::sections(void) const {
  sections_t result;
  for (const SegmentCommand& segment : this->segments()) {
    for (const Section& s: segment.sections()) {
      result.push_back(const_cast<Section*>(&s));
    }
  }
  return it_const_sections{result};
}


// Relocations
it_relocations Binary::relocations(void) {
  relocations_t result;
  for (SegmentCommand& segment : this->segments()) {
    for (Relocation& r: segment.relocations()) {
      result.push_back(&r);
    }
  }

  for (Section& section : this->sections()) {
    for (Relocation& r: section.relocations()) {
      result.push_back(&r);
    }
  }

  return it_relocations{result};
}

it_const_relocations Binary::relocations(void) const {
  relocations_t result;
  for (const SegmentCommand& segment : this->segments()) {
    for (const Relocation& r: segment.relocations()) {
      result.push_back(const_cast<Relocation*>(&r));
    }
  }

  for (const Section& section : this->sections()) {
    for (const Relocation& r: section.relocations()) {
      result.push_back(const_cast<Relocation*>(&r));
    }
  }

  return it_const_relocations{result};
}


// Symbols
// =======

bool Binary::is_exported(const Symbol& symbol) {
  return not symbol.is_external() and symbol.has_export_info();
}

it_exported_symbols Binary::get_exported_symbols(void) {
  return filter_iterator<symbols_t>{std::ref(this->symbols_),
    [] (const Symbol* symbol) { return is_exported(*symbol); }
  };
}


it_const_exported_symbols Binary::get_exported_symbols(void) const {
  return const_filter_iterator<symbols_t>{std::cref(this->symbols_),
    [] (const Symbol* symbol) { return is_exported(*symbol); }
  };
}


bool Binary::is_imported(const Symbol& symbol) {
  return symbol.is_external() and not symbol.has_export_info();
}

it_imported_symbols Binary::get_imported_symbols(void) {
  return filter_iterator<symbols_t>{std::ref(this->symbols_),
    [] (const Symbol* symbol) { return is_imported(*symbol); }
  };
}


it_const_imported_symbols Binary::get_imported_symbols(void) const {
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


const Section& Binary::section_from_offset(uint64_t offset) const {
  it_const_sections sections = this->sections();
  auto&& it_section = std::find_if(
      sections.cbegin(),
      sections.cend(),
      [&offset] (const Section& section) {
        return ((section.offset() <= offset) and
            offset < (section.offset() + section.size()));
      });

  if (it_section == sections.cend()) {
    throw not_found("Unable to find the section");
  }

  return *it_section;
}

Section& Binary::section_from_offset(uint64_t offset) {
  return const_cast<Section&>(static_cast<const Binary*>(this)->section_from_offset(offset));
}

const SegmentCommand& Binary::segment_from_virtual_address(uint64_t virtual_address) const {
  it_const_segments segments = this->segments();
  auto&& it_segment = std::find_if(
      segments.cbegin(),
      segments.cend(),
      [&virtual_address] (const SegmentCommand& segment) {
        return ((segment.virtual_address() <= virtual_address) and
            virtual_address < (segment.virtual_address() + segment.virtual_size()));
      });

  if (it_segment == segments.cend()) {
    std::stringstream ss;
    ss << "0x" << std::hex << virtual_address;
    throw not_found("Unable to find the segment from address " + ss.str());
  }

  return *it_segment;
}

SegmentCommand& Binary::segment_from_virtual_address(uint64_t virtual_address) {
  return const_cast<SegmentCommand&>(static_cast<const Binary*>(this)->segment_from_virtual_address(virtual_address));
}

const SegmentCommand& Binary::segment_from_offset(uint64_t offset) const {
  it_const_segments segments = this->segments();
  auto&& it_segment = std::find_if(
      segments.cbegin(),
      segments.cend(),
      [&offset] (const SegmentCommand& segment) {
        return ((segment.file_offset() <= offset) and
            offset <= (segment.file_offset() + segment.file_size()));
      });

  if (it_segment == segments.cend()) {
    throw not_found("Unable to find the section");
  }

  return *it_segment;
}

SegmentCommand& Binary::segment_from_offset(uint64_t offset) {
  return const_cast<SegmentCommand&>(static_cast<const Binary*>(this)->segment_from_offset(offset));
}



LoadCommand& Binary::insert_command(const LoadCommand& command) {
  LOG(DEBUG) << "Insert command" << std::endl;

  //this->header().nb_cmds(this->header().nb_cmds() + 1);

  //const uint32_t sizeof_header = this->is64_ ? sizeof(mach_header_64) : sizeof(mach_header);


  ////align
  //if (dynamic_cast<const SegmentCommand*>(&command) != nullptr) {
  //  const SegmentCommand& segment = dynamic_cast<const SegmentCommand&>(command);
  //  const uint64_t psize = static_cast<uint64_t>(getpagesize());
  //  if ((segment.file_offset() % psize) > 0) {
  //    uint64_t offset_aligned = segment.file_offset() + (psize - segment.file_offset() % psize);
  //    segment.file_offset(offset_aligned);
  //  }
  //}

  //// Find last offset
  //uint64_t last_offset = std::accumulate(
  //    std::begin(this->commands_),
  //    std::end(this->commands_),
  //    sizeof_header,
  //    [] (uint32_t x, const LoadCommand* cmd) {
  //      return x + cmd->size();
  //    });


  //LOG(DEBUG) << "Last offset: %x", last_offset << std::endl;
  //command.command_offset(last_offset);
  //this->header().sizeof_cmds(this->header().sizeof_cmds() + command.size());
  //this->commands_.push_back(command);
  return *this->commands_.back();

}

std::vector<uint8_t> Binary::raw(void) {
  Builder builder{this};
  return builder.get_build();
}

uint64_t Binary::virtual_address_to_offset(uint64_t virtual_address) const {

  const SegmentCommand& segment = segment_from_virtual_address(virtual_address);

  uint64_t base_address = segment.virtual_address() - segment.file_offset();
  uint64_t offset       = virtual_address - base_address;

  return offset;
}


bool Binary::disable_pie(void) {
  if (this->header().has_flag(HEADER_FLAGS::MH_PIE)) {
    this->header().remove_flag(HEADER_FLAGS::MH_PIE);
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


const std::string& Binary::get_loader(void) const {
  return this->dylinker().name();
}

uint64_t Binary::fat_offset(void) const {
  return this->fat_offset_;
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

// UUID
// ++++
bool Binary::has_uuid(void) const {
  return this->has_command<UUIDCommand>();
}

UUIDCommand& Binary::uuid(void) {
  return this->get_command<UUIDCommand>();
}

const UUIDCommand& Binary::uuid(void) const {
  return this->get_command<UUIDCommand>();
}

// MainCommand
// +++++++++++
bool Binary::has_main_command(void) const {
  return this->has_command<MainCommand>();
}

MainCommand& Binary::main_command(void) {
  return this->get_command<MainCommand>();
}

const MainCommand& Binary::main_command(void) const {
  return this->get_command<MainCommand>();
}

// DylinkerCommand
// +++++++++++++++
bool Binary::has_dylinker(void) const {
  return this->has_command<DylinkerCommand>();
}

DylinkerCommand& Binary::dylinker(void) {
  return this->get_command<DylinkerCommand>();
}

const DylinkerCommand& Binary::dylinker(void) const {
  return this->get_command<DylinkerCommand>();
}

// DyldInfo
// ++++++++
bool Binary::has_dyld_info(void) const {
  return this->has_command<DyldInfo>();
}

DyldInfo& Binary::dyld_info(void) {
  return this->get_command<DyldInfo>();
}

const DyldInfo& Binary::dyld_info(void) const {
  return this->get_command<DyldInfo>();
}

// Function Starts
// +++++++++++++++
bool Binary::has_function_starts(void) const {
  return this->has_command<FunctionStarts>();
}

FunctionStarts& Binary::function_starts(void) {
  return this->get_command<FunctionStarts>();
}

const FunctionStarts& Binary::function_starts(void) const {
  return this->get_command<FunctionStarts>();
}

// Source Version
// ++++++++++++++
bool Binary::has_source_version(void) const {
  return this->has_command<SourceVersion>();
}

SourceVersion& Binary::source_version(void) {
  return this->get_command<SourceVersion>();
}

const SourceVersion& Binary::source_version(void) const {
  return this->get_command<SourceVersion>();
}

// Version Min
// +++++++++++
bool Binary::has_version_min(void) const {
  return this->has_command<VersionMin>();
}

VersionMin& Binary::version_min(void) {
  return this->get_command<VersionMin>();
}

const VersionMin& Binary::version_min(void) const {
  return this->get_command<VersionMin>();
}





void Binary::accept(LIEF::Visitor& visitor) const {
  visitor(this->header());
  for (const LoadCommand& cmd : this->commands()) {
    visitor(cmd);
  }

  for (const Symbol& symbol : this->symbols()) {
    visitor(symbol);
  }
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

