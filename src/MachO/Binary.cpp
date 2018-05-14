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

#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/Builder.hpp"
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
  SegmentCommand& segment_topatch = this->segment_from_virtual_address(address);
  const uint64_t offset = address - segment_topatch.virtual_address();
  std::vector<uint8_t> content = segment_topatch.content();
  std::copy(
      std::begin(patch_value),
      std::end(patch_value),
      content.data() + offset);
  segment_topatch.content(content);

}

void Binary::patch_address(uint64_t address, uint64_t patch_value, size_t size, LIEF::Binary::VA_TYPES) {
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

std::vector<uint8_t> Binary::get_content_from_virtual_address(uint64_t virtual_address, uint64_t size, LIEF::Binary::VA_TYPES) const {
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


std::vector<std::string> Binary::get_abstract_exported_functions(void) const {
  std::vector<std::string> result;
  it_const_exported_symbols syms = this->exported_symbols();
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
  it_const_imported_symbols syms = this->imported_symbols();
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
  return it_libraries{result};
}

it_const_libraries Binary::libraries(void) const {

  libraries_t result;

  for (LoadCommand* library: this->commands_) {
    if (typeid(*library) == typeid(DylibCommand)) {
      result.push_back(dynamic_cast<DylibCommand*>(library));
    }
  }
  return it_const_libraries{result};
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
it_relocations Binary::relocations(void) {
  relocations_t result;
  for (SegmentCommand& segment : this->segments()) {
    result.insert(std::begin(segment.relocations_), std::end(segment.relocations_));
  }

  for (Section& section : this->sections()) {
    result.insert(std::begin(section.relocations_), std::end(section.relocations_));
  }

  if (result.size() != this->relocations_.size()) {
    this->relocations_ = std::move(result);
  }

  return this->relocations_;
}

it_const_relocations Binary::relocations(void) const {
  relocations_t result;
  for (const SegmentCommand& segment : this->segments()) {
    result.insert(std::begin(segment.relocations_), std::end(segment.relocations_));
  }

  for (const Section& section : this->sections()) {
    result.insert(std::begin(section.relocations_), std::end(section.relocations_));
  }

  if (result.size() != this->relocations_.size()) {
    this->relocations_ = std::move(result);
  }

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


const Section& Binary::section_from_virtual_address(uint64_t address) const {
  it_const_sections sections = this->sections();
  auto&& it_section = std::find_if(
      sections.cbegin(),
      sections.cend(),
      [&address] (const Section& section) {
        return ((section.virtual_address() <= address) and
            address < (section.virtual_address() + section.size()));
      });

  if (it_section == sections.cend()) {
    throw not_found("Unable to find the section");
  }

  return *it_section;
}

Section& Binary::section_from_virtual_address(uint64_t address) {
  return const_cast<Section&>(static_cast<const Binary*>(this)->section_from_virtual_address(address));
}

const SegmentCommand& Binary::segment_from_virtual_address(uint64_t virtual_address) const {
  it_const_segments segments = this->segments();
  auto&& it_segment = std::find_if(
      std::begin(segments),
      std::end(segments),
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
      std::begin(segments),
      std::end(segments),
      [&offset] (const SegmentCommand& segment) {
        return ((segment.file_offset() <= offset) and
            offset < (segment.file_offset() + segment.file_size()));
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
  VLOG(VDEBUG) << "Insert command" << std::endl;

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


  //VLOG(VDEBUG) << "Last offset: %x", last_offset << std::endl;
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
  const uint64_t base_address = segment.virtual_address() - segment.file_offset();
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
  std::pair<uint64_t, uint64_t> r = this->va_ranges();
  return address <= r.second and address >= r.first;
}


std::pair<uint64_t, uint64_t> Binary::va_ranges(void) const {

  it_const_segments segments = this->segments();
  uint64_t min = std::accumulate(
      std::begin(segments),
      std::end(segments), uint64_t(-1),
      [] (uint64_t va, const SegmentCommand& segment) {
        return std::min<uint64_t>(segment.virtual_address(), va);
      });


  uint64_t max = std::accumulate(
      std::begin(segments),
      std::end(segments), 0,
      [] (uint64_t va, const SegmentCommand& segment) {
        return std::max<uint64_t>(segment.virtual_address() + segment.virtual_size(), va);
      });

  return {min, max};
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
  return this->has_command<SymbolCommand>();
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

