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

namespace LIEF {
namespace MachO {


template<typename T>
void Builder::build_segments(void) {
  using section_t  = typename T::section;
  using segment_t  = typename T::segment_command;
  using uint__     = typename T::uint;

  VLOG(VDEBUG) << "[+] Rebuilding segments" << std::endl;
  Binary* binary =  this->binaries_.back();
  for (SegmentCommand& segment : binary->segments()) {
    VLOG(VDEBUG) << segment << std::endl;
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
    VLOG(VDEBUG) << "[+] Command offset: " << std::hex << segment.command_offset() << std::endl;

    const auto& content = segment.content();
    if (content.size() != segment.file_size()) {
      throw LIEF::builder_error("content.size() != segment.file_size()");
    }
    //this->raw_.seekp(segment.file_offset());
    //this->raw_.write(content);

    //const size_t original_size = segment.originalData_.size();
    segment.originalData_.clear();

    std::move(
      reinterpret_cast<uint8_t*>(&segment_header),
      reinterpret_cast<uint8_t*>(&segment_header) + sizeof(segment_t),
      std::back_inserter(segment.originalData_));



    // --------
    // Sections
    // --------
    if (segment.sections().size() != segment.numberof_sections()) {
      throw LIEF::builder_error("segment.sections().size() != segment.numberof_sections()");
    }

    it_sections sections = segment.sections();
    for (uint32_t i = 0; i < segment.numberof_sections(); ++i) {
      const Section& section = sections[i];
      VLOG(VDEBUG) << section << std::endl;
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
      if (std::is_same<section_t, section_64>::value) { // TODO: Move to if constexpr when LIEF will use C++17
        reinterpret_cast<section_64*>(&header)->reserved3 = static_cast<uint32_t>(section.reserved3());
      }

      std::move(
        reinterpret_cast<uint8_t*>(&header),
        reinterpret_cast<uint8_t*>(&header) + sizeof(section_t),
        std::back_inserter(segment.originalData_));

    }
  }

} // build_segment


template<typename T>
void Builder::build_symbols(void) {
#if 0
  using nlist_t  = typename T::nlist;

  auto itSymbolCommand = std::find_if(
        std::begin(this->binary_->commands_),
        std::end(this->binary_->commands_),
        [] (const LoadCommand* command) {
          return command->command() == LOAD_COMMAND_TYPES::LC_SYMTAB;
        });
  if (itSymbolCommand == std::end(this->binary_->commands_)) {
    VLOG(VDEBUG) << "[-] No symbols" << std::endl;
    return;
  }

  VLOG(VDEBUG) << "[+] Building symbols" << std::endl;
  const SymbolCommand* symbol_command = static_cast<const SymbolCommand*>(*itSymbolCommand);
  symtab_command command;

  command.cmd     = static_cast<uint32_t>(symbol_command->command());
  command.cmdsize = static_cast<uint32_t>(symbol_command->size());
  command.symoff  = static_cast<uint32_t>(symbol_command->symbol_offset());
  command.nsyms   = static_cast<uint32_t>(symbol_command->numberof_symbols());
  command.stroff  = static_cast<uint32_t>(symbol_command->strings_offset());



  command.strsize = static_cast<uint32_t>(symbol_command->strings_size() + delta);

  uint64_t loadCommandsOffset = symbol_command->command_offset();

  this->raw_.seekp(loadCommandsOffset);
  this->raw_.write(reinterpret_cast<uint8_t*>(&command), sizeof(symtab_command));

  uint32_t string_idx = 1;
  for (size_t i = 0; i < this->binary_->symbols_.size(); ++i) {
    nlist_t symbol;
    const auto& binary_symbol = this->binary_->symbols_[i];
    if (not binary_symbol->name().empty()) {
      const std::string& name = binary_symbol->name();
      const uint32_t name_offset = symbol_command->strings_offset() + string_idx;


      this->raw_.seekp(name_offset);
      this->raw_.write(reinterpret_cast<const uint8_t*>(name.data()), name.size() + 1);

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

    this->raw_.seekp(offset);
    this->raw_.write(reinterpret_cast<const uint8_t*>(&symbol), sizeof(nlist_t));
  }
#endif
} // build_symbols


template<typename T>
void Builder::build(DylibCommand* library) {
  VLOG(VDEBUG) << "Build Dylib '" << library->name() << "'";

  const uint32_t raw_size = sizeof(dylib_command) + library->name().size() + 1;
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  if (library->originalData_.size() != size_needed or
      library->size() != size_needed) {
    LOG(WARNING) << "Not enough spaces to rebuild " << library->name() << ": Skip!";
    LOG(WARNING) << std::hex << library->originalData_.size() << " vs " << size_needed;

  }

  dylib_command raw_cmd;
  std::fill(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(dylib_command),
      0);

  raw_cmd.cmd                         = static_cast<uint32_t>(library->command());
  raw_cmd.cmdsize                     = static_cast<uint32_t>(size_needed);
  raw_cmd.dylib.name                  = static_cast<uint32_t>(sizeof(dylib_command));
  raw_cmd.dylib.timestamp             = static_cast<uint32_t>(library->timestamp());
  raw_cmd.dylib.current_version       = static_cast<uint32_t>(DylibCommand::version2int(library->current_version()));
  raw_cmd.dylib.compatibility_version = static_cast<uint32_t>(DylibCommand::version2int(library->compatibility_version()));

  library->size_ = size_needed;
  library->originalData_.clear();

  // Write Header
  std::move(
    reinterpret_cast<uint8_t*>(&raw_cmd),
    reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(raw_cmd),
    std::back_inserter(library->originalData_));

  // Write String
  const std::string& libname = library->name();
  std::move(
    std::begin(libname),
    std::end(libname),
    std::back_inserter(library->originalData_));
  library->originalData_.push_back(0);
  library->originalData_.insert(std::end(library->originalData_), padding, 0);
}


template <typename T>
void Builder::build(DylinkerCommand* linker) {

  VLOG(VDEBUG) << "Build dylinker '" << linker->name() << "'";
  const uint32_t raw_size = sizeof(dylinker_command) + linker->name().size() + 1;
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  if (linker->originalData_.size() != size_needed or
      linker->size() != size_needed) {
    LOG(WARNING) << "Not enough spaces to rebuild " << linker->name() << ": Skip!";
    LOG(WARNING) << std::hex << linker->originalData_.size() << " vs " << size_needed;
  }

  dylinker_command raw_cmd;
  std::fill(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(dylinker_command),
      0);

  raw_cmd.cmd     = static_cast<uint32_t>(linker->command());
  raw_cmd.cmdsize = static_cast<uint32_t>(size_needed);
  raw_cmd.name    = static_cast<uint32_t>(sizeof(dylinker_command));

  linker->size_ = size_needed;
  linker->originalData_.clear();

  // Write Header
  std::move(
    reinterpret_cast<uint8_t*>(&raw_cmd),
    reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(raw_cmd),
    std::back_inserter(linker->originalData_));

  // Write String
  const std::string& linkpath = linker->name();
  std::move(
    std::begin(linkpath),
    std::end(linkpath),
    std::back_inserter(linker->originalData_));
  linker->originalData_.push_back(0);
  linker->originalData_.insert(std::end(linker->originalData_), padding, 0);
}

template<class T>
void Builder::build(VersionMin* version_min) {
  VLOG(VDEBUG) << "Build '" << to_string(version_min->command()) << "'";
  const uint32_t raw_size = sizeof(version_min_command);
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  version_min_command raw_cmd;
  const VersionMin::version_t& version = version_min->version();
  const VersionMin::version_t& sdk = version_min->sdk();

  std::fill(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(version_min_command),
      0);

  raw_cmd.cmd     = static_cast<uint32_t>(version_min->command());
  raw_cmd.cmdsize = static_cast<uint32_t>(version_min->size());
  raw_cmd.version = static_cast<uint32_t>(version[0] << 16 | version[1] << 8 | version[2]);
  raw_cmd.sdk     = static_cast<uint32_t>(sdk[0] << 16 | sdk[1] << 8 | sdk[2]);

  version_min->size_ = sizeof(version_min_command);
  version_min->originalData_.clear();
  std::move(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(version_min_command),
      std::back_inserter(version_min->originalData_));
  version_min->originalData_.insert(std::end(version_min->originalData_), padding, 0);

}


template<class T>
void Builder::build(SourceVersion* source_version) {
  VLOG(VDEBUG) << "Build '" << to_string(source_version->command()) << "'";
  const uint32_t raw_size = sizeof(source_version_command);
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  source_version_command raw_cmd;

  std::fill(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(source_version_command),
      0);
  const SourceVersion::version_t& version = source_version->version();
  raw_cmd.cmd     = static_cast<uint32_t>(source_version->command());
  raw_cmd.cmdsize = static_cast<uint32_t>(source_version->size());
  raw_cmd.version = static_cast<uint64_t>(
      static_cast<uint64_t>(version[0]) << 40 |
      static_cast<uint64_t>(version[1]) << 30 |
      static_cast<uint64_t>(version[2]) << 20 |
      static_cast<uint64_t>(version[3]) << 10 |
      static_cast<uint64_t>(version[4]));

  source_version->size_ = sizeof(source_version_command);
  source_version->originalData_.clear();
  std::move(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(source_version_command),
      std::back_inserter(source_version->originalData_));
  source_version->originalData_.insert(std::end(source_version->originalData_), padding, 0);

}


template<class T>
void Builder::build(MainCommand* main_cmd) {
  VLOG(VDEBUG) << "Build '" << to_string(main_cmd->command()) << "'";
  const uint32_t raw_size = sizeof(entry_point_command);
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  entry_point_command raw_cmd;

  std::fill(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(entry_point_command),
      0);

  raw_cmd.cmd       = static_cast<uint32_t>(main_cmd->command());
  raw_cmd.cmdsize   = static_cast<uint32_t>(main_cmd->size());
  raw_cmd.entryoff  = static_cast<uint64_t>(main_cmd->entrypoint());
  raw_cmd.stacksize = static_cast<uint64_t>(main_cmd->stack_size());

  main_cmd->size_ = sizeof(entry_point_command);
  main_cmd->originalData_.clear();
  std::move(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(entry_point_command),
      std::back_inserter(main_cmd->originalData_));
  main_cmd->originalData_.insert(std::end(main_cmd->originalData_), padding, 0);
}


template<class T>
void Builder::build(DyldInfo* dyld_info) {
  VLOG(VDEBUG) << "Build '" << to_string(dyld_info->command()) << "'";

  dyld_info->update_export_trie().update_rebase_info().update_binding_info();

  const uint32_t raw_size = sizeof(dyld_info_command);
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  dyld_info_command raw_cmd;

  std::fill(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(dyld_info_command),
      0);

  raw_cmd.cmd     = static_cast<uint32_t>(dyld_info->command());
  raw_cmd.cmdsize = static_cast<uint32_t>(dyld_info->size());

  std::tie(raw_cmd.rebase_off,    raw_cmd.rebase_size)    = dyld_info->rebase();
  std::tie(raw_cmd.bind_off,      raw_cmd.bind_size)      = dyld_info->bind();
  std::tie(raw_cmd.weak_bind_off, raw_cmd.weak_bind_size) = dyld_info->weak_bind();
  std::tie(raw_cmd.lazy_bind_off, raw_cmd.lazy_bind_size) = dyld_info->lazy_bind();
  std::tie(raw_cmd.export_off,    raw_cmd.export_size)    = dyld_info->export_info();

  dyld_info->size_ = sizeof(dyld_info_command);
  dyld_info->originalData_.clear();
  std::move(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(dyld_info_command),
      std::back_inserter(dyld_info->originalData_));
  dyld_info->originalData_.insert(std::end(dyld_info->originalData_), padding, 0);


  // Write Back Content

  // Rebase opcodes
  // ==============
  {
    const buffer_t& rebase_opcodes = dyld_info->rebase_opcodes();
    LOG_IF(rebase_opcodes.size() != raw_cmd.rebase_size, WARNING) << "Rebase opcodes size is different from metadata";

    SegmentCommand* rebase_segment = this->binary_->segment_from_offset(raw_cmd.rebase_off);

    CHECK_NE(rebase_segment, nullptr);
    uint64_t relative_offset = raw_cmd.rebase_off - rebase_segment->file_offset();

    std::vector<uint8_t> content = rebase_segment->content();

    std::move(
        std::begin(rebase_opcodes),
        std::end(rebase_opcodes),
        content.data() + relative_offset);
    rebase_segment->content(std::move(content));
  }

  // Bind opcodes
  // ============
  {
    const buffer_t& bind_opcodes = dyld_info->bind_opcodes();
    LOG_IF(bind_opcodes.size() != raw_cmd.bind_size, WARNING) << "Bind opcodes size is different from metadata";

    SegmentCommand* bind_segment = this->binary_->segment_from_offset(raw_cmd.bind_off);
    CHECK_NE(bind_segment, nullptr);

    uint64_t relative_offset = raw_cmd.bind_off - bind_segment->file_offset();
    std::vector<uint8_t> content = bind_segment->content();
    std::move(
        std::begin(bind_opcodes),
        std::end(bind_opcodes),
        content.data() + relative_offset);
    bind_segment->content(std::move(content));
  }


  // Weak Bind opcodes
  // =================
  {
    const buffer_t& weak_bind_opcodes = dyld_info->weak_bind_opcodes();
    LOG_IF(weak_bind_opcodes.size() != raw_cmd.weak_bind_size, WARNING) << "Weak Bind opcodes size is different from metadata";

    SegmentCommand* weak_bind_segment = this->binary_->segment_from_offset(raw_cmd.weak_bind_off);
    CHECK_NE(weak_bind_segment, nullptr);
    uint64_t relative_offset = raw_cmd.weak_bind_off - weak_bind_segment->file_offset();
    std::vector<uint8_t> content = weak_bind_segment->content();
    std::move(
        std::begin(weak_bind_opcodes),
        std::end(weak_bind_opcodes),
        content.data() + relative_offset);
    weak_bind_segment->content(std::move(content));
  }


  // Lazy Bind opcodes
  // =================
  {
    const buffer_t& lazy_bind_opcodes = dyld_info->lazy_bind_opcodes();
    LOG_IF(lazy_bind_opcodes.size() != raw_cmd.lazy_bind_size, WARNING) << "Lazy Bind opcodes size is different from metadata";

    SegmentCommand* lazy_bind_segment = this->binary_->segment_from_offset(raw_cmd.lazy_bind_off);
    CHECK_NE(lazy_bind_segment, nullptr);
    uint64_t relative_offset = raw_cmd.lazy_bind_off - lazy_bind_segment->file_offset();
    std::vector<uint8_t> content = lazy_bind_segment->content();
    std::move(
        std::begin(lazy_bind_opcodes),
        std::end(lazy_bind_opcodes),
        content.data() + relative_offset);
    lazy_bind_segment->content(std::move(content));
  }


  // Export trie
  // ===========
  {
    const buffer_t& export_trie = dyld_info->export_trie();
    LOG_IF(export_trie.size() != raw_cmd.export_size, WARNING) << "Export trie size is different from metadata";

    SegmentCommand* export_segment = this->binary_->segment_from_offset(raw_cmd.export_off);
    CHECK_NE(export_segment, nullptr);
    uint64_t relative_offset = raw_cmd.export_off - export_segment->file_offset();
    std::vector<uint8_t> content = export_segment->content();
    std::move(
        std::begin(export_trie),
        std::end(export_trie),
        content.data() + relative_offset);
    export_segment->content(std::move(content));
  }


}


template<class T>
void Builder::build(FunctionStarts* function_starts) {
  VLOG(VDEBUG) << "Build '" << to_string(function_starts->command()) << "'";

  std::vector<uint8_t> packed_functions;

  packed_functions.reserve(1024 * sizeof(uint64_t));

  uint64_t prev_address = 0;
  for (uint64_t address : function_starts->functions()) {

    uint64_t delta = address - prev_address;
    std::vector<uint8_t> encoded = LEB128::uencode(delta);

    std::move(
        std::begin(encoded),
        std::end(encoded),
        std::back_inserter(packed_functions));
    prev_address = address;
  }

  // Pad to pointer size
  size_t padding = align(packed_functions.size(), sizeof(typename T::uint)) -  packed_functions.size();
  packed_functions.insert(std::end(packed_functions), padding, 0);

  // Find the segment associated with LC_FUNCTION_STARTS
  SegmentCommand* segment = this->binary_->segment_from_offset(function_starts->data_offset());

  CHECK_NE(segment, nullptr);
  std::vector<uint8_t> content = segment->content();
  uint64_t relative_offset = function_starts->data_offset() - segment->file_offset();
  std::move(
      std::begin(packed_functions),
      std::end(packed_functions),
      content.data() + relative_offset);
  segment->content(std::move(content));


  // Write back the 'linkedit' structure
  const uint32_t raw_size = sizeof(linkedit_data_command);
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t struct_padding = size_needed - raw_size;

  linkedit_data_command raw_cmd;

  std::fill(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(linkedit_data_command),
      0);

  raw_cmd.cmd       = static_cast<uint32_t>(function_starts->command());
  raw_cmd.cmdsize   = static_cast<uint32_t>(function_starts->size());
  raw_cmd.dataoff   = static_cast<uint64_t>(function_starts->data_offset());
  raw_cmd.datasize  = static_cast<uint64_t>(function_starts->data_size());

  function_starts->size_ = sizeof(linkedit_data_command);
  function_starts->originalData_.clear();

  std::move(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(linkedit_data_command),
      std::back_inserter(function_starts->originalData_));
  function_starts->originalData_.insert(std::end(function_starts->originalData_), struct_padding, 0);
}


template<class T>
void Builder::build(SymbolCommand* symbol_command) {

 // +---------------------+
 // |                     |
 // |  symtab_command     |
 // |                     |
 // +---------------------+
 // |                     |
 // |  n_list             |
 // |                     |
 // +---------------------+
 // |                     |
 // | string table        |
 // |                     |
 // +---------------------+

  using nlist_t = typename T::nlist;
  using uint    = typename T::uint;

  symtab_command symtab;

  auto cmp_string = [] (const std::string& a, const std::string& b) {
    return (a.size() >= b.size() and a != b);
  };

  std::vector<Symbol*> symbols;
  symbols.reserve(this->binary_->symbols().size());


  // 1. Fill the string table
  // -------------------------------------
  std::set<std::string, decltype(cmp_string)> string_table{cmp_string};
  std::vector<std::string> string_table_opt;
  for (Symbol& s : this->binary_->symbols()) {
    if (s.origin() == SYMBOL_ORIGINS::SYM_ORIGIN_LC_SYMTAB) {
      string_table.insert(s.name());
      symbols.push_back(&s);
    }
  }

  std::copy_if(
      std::begin(string_table),
      std::end(string_table),
      std::back_inserter(string_table_opt),
      [&string_table_opt] (const std::string& name) {

        auto&& it = std::find_if(
            std::begin(string_table_opt),
            std::end(string_table_opt),
            [&name] (const std::string& nameopt) {
              return nameopt.substr(nameopt.size() - name.size()) == name ;
            });

        return (it == std::end(string_table_opt));
      });

  std::vector<uint8_t> raw_symbol_names;

  // 0 index is reserved
  raw_symbol_names.push_back(0);
  for (const std::string& name : string_table_opt) {
    std::move(
        std::begin(name), std::end(name),
        std::back_inserter(raw_symbol_names));
    raw_symbol_names.push_back(0);
  }

  // If the table is smaller than th original one, fill with 0
  if (raw_symbol_names.size() < symbol_command->strings_size()) {
    raw_symbol_names.insert(
        std::end(raw_symbol_names),
        symbol_command->strings_size() - raw_symbol_names.size() ,
        0
    );
  }

  size_t padding = align(raw_symbol_names.size(), sizeof(uint)) - raw_symbol_names.size();
  raw_symbol_names.insert(std::end(raw_symbol_names), padding, 0);


  // To be removed later
  CHECK(raw_symbol_names.size() <= symbol_command->strings_size()) << std::hex << std::showbase << raw_symbol_names.size() << " vs " << symbol_command->strings_size();

  // Update the segment handling
  // the string table
  SegmentCommand* segment = this->binary_->segment_from_offset(symbol_command->strings_offset());
  CHECK_NE(segment, nullptr);

  std::vector<uint8_t> content = segment->content();
  uint64_t relative_offset = symbol_command->strings_offset() - segment->file_offset();
  std::move(
      std::begin(raw_symbol_names),
      std::end(raw_symbol_names),
      content.data() + relative_offset);
  segment->content(std::move(content));

  // 2. Fill the n_list table
  // -------------------------------------
  std::vector<uint8_t> nlist_table;
  nlist_table.reserve(symbols.size() * sizeof(nlist_t));
  for (Symbol* sym : symbols) {
    const std::string& name = sym->name();
    auto&& it_name = std::search(
        std::begin(raw_symbol_names),
        std::end(raw_symbol_names),
        name.c_str(),
        name.c_str() + name.size() + 1);

    CHECK_NE(it_name, std::end(raw_symbol_names));
    const size_t name_offset = std::distance(std::begin(raw_symbol_names), it_name);

    nlist_t nl;
    nl.n_strx  = static_cast<uint32_t>(name_offset);
    nl.n_type  = static_cast<uint8_t>(sym->type());
    nl.n_sect  = static_cast<uint32_t>(sym->numberof_sections());
    nl.n_desc  = static_cast<uint16_t>(sym->description());
    nl.n_value = static_cast<uint>(sym->value());

    nlist_table.insert(
      std::end(nlist_table),
      reinterpret_cast<const uint8_t*>(&nl),
      reinterpret_cast<const uint8_t*>(&nl) + sizeof(nlist_t)
    );
  }

  CHECK(nlist_table.size() == symbol_command->numberof_symbols() * sizeof(nlist_t));

  segment = this->binary_->segment_from_offset(symbol_command->symbol_offset());
  CHECK_NE(segment, nullptr);

  content = segment->content();
  relative_offset = symbol_command->symbol_offset() - segment->file_offset();
  std::move(
      std::begin(nlist_table),
      std::end(nlist_table),
      content.data() + relative_offset);
  segment->content(std::move(content));

  // 3. Fill the Header
  std::fill(
      reinterpret_cast<uint8_t*>(&symtab),
      reinterpret_cast<uint8_t*>(&symtab) + sizeof(symtab_command),
      0);

  //const uint32_t size_needed = sizeof(symtab_command) + nlist_table.size() + raw_symbol_names.size();
  symtab.cmd     = static_cast<uint32_t>(symbol_command->command());
  symtab.cmdsize = static_cast<uint32_t>(symbol_command->size());
  symtab.symoff  = static_cast<uint32_t>(symbol_command->symbol_offset());    // **Usually** After the header
  symtab.nsyms   = static_cast<uint32_t>(symbol_command->numberof_symbols());
  symtab.stroff  = static_cast<uint32_t>(symbol_command->strings_offset());   // **Usually** After nlist table


  // TODO: Improve
  // Update linkedit segment
  SegmentCommand& linkedit = *this->binary_->get_segment("__LINKEDIT");
  size_t delta = linkedit.file_offset() + linkedit.file_size();
  delta = delta - (symbol_command->strings_offset() + symbol_command->strings_size());
  //std::cout << std::hex << "delta:" << delta << std::endl;
  symtab.strsize = static_cast<uint32_t>(symbol_command->strings_size() + delta);

  symbol_command->originalData_.clear();
  symbol_command->originalData_.reserve(sizeof(symtab_command));

  std::move(
      reinterpret_cast<const uint8_t*>(&symtab),
      reinterpret_cast<const uint8_t*>(&symtab) + sizeof(symtab_command),
      std::back_inserter(symbol_command->originalData_)
  );

}


template<class T>
void Builder::build(DynamicSymbolCommand* symbol_command) {
  dysymtab_command rawcmd;

  std::fill(
      reinterpret_cast<uint8_t*>(&rawcmd),
      reinterpret_cast<uint8_t*>(&rawcmd) + sizeof(dysymtab_command),
      0);

  rawcmd.cmd            = static_cast<uint32_t>(symbol_command->command());
  rawcmd.cmdsize        = static_cast<uint32_t>(symbol_command->size());
  rawcmd.ilocalsym      = static_cast<uint32_t>(symbol_command->idx_local_symbol());
  rawcmd.nlocalsym      = static_cast<uint32_t>(symbol_command->nb_local_symbols());
  rawcmd.iextdefsym     = static_cast<uint32_t>(symbol_command->idx_external_define_symbol());
  rawcmd.nextdefsym     = static_cast<uint32_t>(symbol_command->nb_external_define_symbols());
  rawcmd.iundefsym      = static_cast<uint32_t>(symbol_command->idx_undefined_symbol());
  rawcmd.nundefsym      = static_cast<uint32_t>(symbol_command->nb_undefined_symbols());
  rawcmd.tocoff         = static_cast<uint32_t>(symbol_command->toc_offset());
  rawcmd.ntoc           = static_cast<uint32_t>(symbol_command->nb_toc());
  rawcmd.modtaboff      = static_cast<uint32_t>(symbol_command->module_table_offset());
  rawcmd.nmodtab        = static_cast<uint32_t>(symbol_command->nb_module_table());
  rawcmd.extrefsymoff   = static_cast<uint32_t>(symbol_command->external_reference_symbol_offset());
  rawcmd.nextrefsyms    = static_cast<uint32_t>(symbol_command->nb_external_reference_symbols());
  rawcmd.indirectsymoff = static_cast<uint32_t>(symbol_command->indirect_symbol_offset());
  rawcmd.nindirectsyms  = static_cast<uint32_t>(symbol_command->nb_indirect_symbols());
  rawcmd.extreloff      = static_cast<uint32_t>(symbol_command->external_relocation_offset());
  rawcmd.nextrel        = static_cast<uint32_t>(symbol_command->nb_external_relocations());
  rawcmd.locreloff      = static_cast<uint32_t>(symbol_command->local_relocation_offset());
  rawcmd.nlocrel        = static_cast<uint32_t>(symbol_command->nb_local_relocations());

  symbol_command->originalData_.clear();
  symbol_command->originalData_.reserve(sizeof(dysymtab_command));

  std::move(
      reinterpret_cast<const uint8_t*>(&rawcmd),
      reinterpret_cast<const uint8_t*>(&rawcmd) + sizeof(dysymtab_command),
      std::back_inserter(symbol_command->originalData_)
  );
}

template<class T>
void Builder::build(DataInCode* datacode) {
  VLOG(VDEBUG) << "Build '" << to_string(datacode->command()) << "'";

  linkedit_data_command raw_cmd;

  std::fill(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(linkedit_data_command),
      0);

  raw_cmd.cmd       = static_cast<uint32_t>(datacode->command());
  raw_cmd.cmdsize   = static_cast<uint32_t>(datacode->size());
  raw_cmd.dataoff   = static_cast<uint64_t>(datacode->data_offset());
  raw_cmd.datasize  = static_cast<uint64_t>(datacode->data_size());

  datacode->size_ = sizeof(linkedit_data_command);
  datacode->originalData_.clear();

  std::move(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(linkedit_data_command),
      std::back_inserter(datacode->originalData_));
  //code_signature->originalData_.insert(std::end(code_signature->originalData_), struct_padding, 0);

}

template<class T>
void Builder::build(CodeSignature* code_signature) {
  VLOG(VDEBUG) << "Build '" << to_string(code_signature->command()) << "'";

  linkedit_data_command raw_cmd;

  std::fill(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(linkedit_data_command),
      0);

  raw_cmd.cmd       = static_cast<uint32_t>(code_signature->command());
  raw_cmd.cmdsize   = static_cast<uint32_t>(code_signature->size());
  raw_cmd.dataoff   = static_cast<uint64_t>(code_signature->data_offset());
  raw_cmd.datasize  = static_cast<uint64_t>(code_signature->data_size());

  code_signature->size_ = sizeof(linkedit_data_command);
  code_signature->originalData_.clear();

  std::move(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(linkedit_data_command),
      std::back_inserter(code_signature->originalData_));
  //code_signature->originalData_.insert(std::end(code_signature->originalData_), struct_padding, 0);
}

template<class T>
void Builder::build(SegmentSplitInfo* ssi) {
  VLOG(VDEBUG) << "Build '" << to_string(ssi->command()) << "'";

  linkedit_data_command raw_cmd;

  std::fill(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(linkedit_data_command),
      0);

  raw_cmd.cmd       = static_cast<uint32_t>(ssi->command());
  raw_cmd.cmdsize   = static_cast<uint32_t>(ssi->size());
  raw_cmd.dataoff   = static_cast<uint64_t>(ssi->data_offset());
  raw_cmd.datasize  = static_cast<uint64_t>(ssi->data_size());

  ssi->size_ = sizeof(linkedit_data_command);
  ssi->originalData_.clear();

  std::move(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(linkedit_data_command),
      std::back_inserter(ssi->originalData_));
}

template<class T>
void Builder::build(SubFramework* sf) {
  sub_framework_command raw_cmd;

  const uint32_t raw_size = sizeof(sub_framework_command) + sf->umbrella().size() + 1;
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  if (sf->originalData_.size() != size_needed or
      sf->size() != size_needed) {
    LOG(WARNING) << "Not enough spaces to rebuild " << sf->umbrella() << ": Skip!";
    LOG(WARNING) << std::hex << sf->originalData_.size() << " vs " << size_needed;
  }

  std::fill(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(sub_framework_command),
      0);

  raw_cmd.cmd      = static_cast<uint32_t>(sf->command());
  raw_cmd.cmdsize  = static_cast<uint32_t>(size_needed);
  raw_cmd.umbrella = static_cast<uint32_t>(sizeof(sub_framework_command));

  sf->size_ = size_needed;
  sf->originalData_.clear();

  // Write Header
  std::move(
    reinterpret_cast<uint8_t*>(&raw_cmd),
    reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(raw_cmd),
    std::back_inserter(sf->originalData_));

  // Write String
  const std::string& um = sf->umbrella();
  std::move(
    std::begin(um),
    std::end(um),
    std::back_inserter(sf->originalData_));
  sf->originalData_.push_back(0);
  sf->originalData_.insert(std::end(sf->originalData_), padding, 0);
}

template<class T>
void Builder::build(DyldEnvironment* de) {
  dylinker_command raw_cmd;

  const uint32_t raw_size = sizeof(dylinker_command) + de->value().size() + 1;
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  if (de->originalData_.size() != size_needed or
      de->size() != size_needed) {
    LOG(WARNING) << "Not enough spaces to rebuild " << de->value() << ": Skip!";
    LOG(WARNING) << std::hex << de->originalData_.size() << " vs " << size_needed;
  }

  std::fill(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(dylinker_command),
      0);

  raw_cmd.cmd      = static_cast<uint32_t>(de->command());
  raw_cmd.cmdsize  = static_cast<uint32_t>(size_needed);
  raw_cmd.name     = static_cast<uint32_t>(sizeof(dylinker_command));

  de->size_ = size_needed;
  de->originalData_.clear();

  // Write Header
  std::move(
    reinterpret_cast<uint8_t*>(&raw_cmd),
    reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(raw_cmd),
    std::back_inserter(de->originalData_));

  // Write String
  const std::string& value = de->value();
  std::move(
    std::begin(value),
    std::end(value),
    std::back_inserter(de->originalData_));
  de->originalData_.push_back(0);
  de->originalData_.insert(std::end(de->originalData_), padding, 0);
}


template<class T>
void Builder::build(BuildVersion* bv) {
  build_version_command raw_cmd;
  const BuildVersion::tools_list_t& tools = bv->tools();

  const uint32_t raw_size    = sizeof(build_version_command) + tools.size() * sizeof(build_tool_version);
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding     = size_needed - raw_size;

  if (bv->originalData_.size() != size_needed or
      bv->size() != size_needed) {
    //LOG(WARNING) << "Not enough spaces to rebuild " << bv->value() << ": Skip!";
    //LOG(WARNING) << std::hex << bv->originalData_.size() << " vs " << size_needed;
  }

  const BuildVersion::version_t& minos    = bv->minos();
  const BuildVersion::version_t& sdk      = bv->sdk();

  std::fill(
      reinterpret_cast<uint8_t*>(&raw_cmd),
      reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(build_version_command),
      0);

  raw_cmd.cmd      = static_cast<uint32_t>(bv->command());
  raw_cmd.cmdsize  = static_cast<uint32_t>(size_needed);

  raw_cmd.minos    = static_cast<uint32_t>(minos[0] << 16 | minos[1] << 8 | minos[2]);
  raw_cmd.sdk      = static_cast<uint32_t>(sdk[0] << 16 | sdk[1] << 8 | sdk[2]);
  raw_cmd.platform = static_cast<uint32_t>(bv->platform());
  raw_cmd.ntools   = tools.size();
  //raw_cmd.name     = static_cast<uint32_t>(sizeof(build_version_command));
  std::vector<uint8_t> raw_tools(raw_cmd.ntools * sizeof(build_tool_version), 0);
  auto tools_array = reinterpret_cast<build_tool_version*>(raw_tools.data());
  for (size_t i = 0; i < tools.size(); ++i) {
    BuildToolVersion::version_t version = tools[i].version();
    tools_array[i].tool    = static_cast<uint32_t>(tools[i].tool());
    tools_array[i].version = static_cast<uint32_t>(version[0] << 16 | version[1] << 8 | version[2]);
  }

  bv->size_ = size_needed;
  bv->originalData_.clear();

  // Write Header
  std::move(
    reinterpret_cast<uint8_t*>(&raw_cmd),
    reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(raw_cmd),
    std::back_inserter(bv->originalData_));

  std::move(
    std::begin(raw_tools),
    std::end(raw_tools),
    std::back_inserter(bv->originalData_));

  bv->originalData_.insert(std::end(bv->originalData_), padding, 0);
}



}
}
