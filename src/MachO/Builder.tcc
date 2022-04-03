/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include "LIEF/utils.hpp"

#include "LIEF/MachO/Builder.hpp"
#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"
#include "LIEF/MachO/Section.hpp"
#include "LIEF/MachO/DylibCommand.hpp"
#include "LIEF/MachO/DylinkerCommand.hpp"
#include "LIEF/MachO/VersionMin.hpp"
#include "LIEF/MachO/EnumToString.hpp"
#include "LIEF/MachO/SourceVersion.hpp"
#include "LIEF/MachO/MainCommand.hpp"
#include "LIEF/MachO/DyldInfo.hpp"
#include "LIEF/MachO/FunctionStarts.hpp"
#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/SymbolCommand.hpp"
#include "LIEF/MachO/DynamicSymbolCommand.hpp"
#include "LIEF/MachO/DataInCode.hpp"
#include "LIEF/MachO/CodeSignature.hpp"
#include "LIEF/MachO/SegmentSplitInfo.hpp"
#include "LIEF/MachO/SubFramework.hpp"
#include "LIEF/MachO/DyldEnvironment.hpp"
#include "LIEF/MachO/ThreadCommand.hpp"
#include "LIEF/MachO/BuildVersion.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {


template<typename T>
ok_error_t Builder::build_segments() {
  using section_t  = typename T::section;
  using segment_t  = typename T::segment_command;
  using uint__     = typename T::uint;

  LIEF_DEBUG("[+] Rebuilding segments");
  Binary* binary = binaries_.back();
  for (SegmentCommand& segment : binary->segments()) {
    LIEF_DEBUG("{}", segment);
    segment_t segment_header;
    std::memset(&segment_header, 0, sizeof(segment_header));

    segment_header.cmd      = static_cast<uint32_t>(segment.command());
    segment_header.cmdsize  = static_cast<uint32_t>(segment.size());

    const std::string& seg_name = segment.name();
    const uint32_t segname_length = std::min<uint32_t>(seg_name.size() + 1,
                                                       sizeof(segment_header.segname));
    std::copy(seg_name.c_str(), seg_name.c_str() + segname_length,
              std::begin(segment_header.segname));

    segment_header.vmaddr   = static_cast<uint__>(segment.virtual_address());
    segment_header.vmsize   = static_cast<uint__>(segment.virtual_size());
    segment_header.fileoff  = static_cast<uint__>(segment.file_offset());
    segment_header.filesize = static_cast<uint__>(segment.file_size());
    segment_header.maxprot  = static_cast<uint32_t>(segment.max_protection());
    segment_header.initprot = static_cast<uint32_t>(segment.init_protection());
    segment_header.nsects   = static_cast<uint32_t>(segment.numberof_sections());
    segment_header.flags    = static_cast<uint32_t>(segment.flags());
    LIEF_DEBUG("  - Command offset: 0x{:x}", segment.command_offset());

    const auto& content = segment.content();
    if (content.size() != segment.file_size()) {
      LIEF_ERR("{} content size and file_size are differents: 0x{:x} vs 0x{:x}",
               segment.name(), content.size(), segment.file_size());
      return make_error_code(lief_errors::build_error);
    }

    segment.original_data_.clear();

    std::move(reinterpret_cast<uint8_t*>(&segment_header),
              reinterpret_cast<uint8_t*>(&segment_header) + sizeof(segment_t),
              std::back_inserter(segment.original_data_));

    // --------
    // Sections
    // --------
    if (segment.sections().size() != segment.numberof_sections()) {
      LIEF_ERR("segment.sections().size() != segment.numberof_sections()");
      return make_error_code(lief_errors::build_error);
    }

    SegmentCommand::it_sections sections = segment.sections();
    for (uint32_t i = 0; i < segment.numberof_sections(); ++i) {
      const Section& section = sections[i];
      const std::string& sec_name = section.name();
      const std::string& segment_name = segment.name();
      LIEF_DEBUG("{}", section);
      section_t header;
      std::memset(&header, 0, sizeof(header));

      const auto segname_length = std::min<uint32_t>(segment_name.size() + 1, sizeof(header.segname));
      std::copy(segment_name.c_str(), segment_name.c_str() + segname_length,
                std::begin(header.segname));

      const auto secname_length = std::min<uint32_t>(sec_name.size() + 1, sizeof(header.sectname));
      std::copy(sec_name.c_str(), sec_name.c_str() + secname_length,
                std::begin(header.sectname));

      header.addr      = static_cast<uint__>(section.address());
      header.size      = static_cast<uint__>(section.size());
      header.offset    = static_cast<uint32_t>(section.offset());
      header.align     = static_cast<uint32_t>(section.alignment());
      header.reloff    = static_cast<uint32_t>(section.relocation_offset());
      header.nreloc    = static_cast<uint32_t>(section.numberof_relocations());
      header.flags     = static_cast<uint32_t>(section.raw_flags());
      header.reserved1 = static_cast<uint32_t>(section.reserved1());
      header.reserved2 = static_cast<uint32_t>(section.reserved2());
      if (std::is_same<section_t, details::section_64>::value) { // TODO: Move to if constexpr when LIEF will use C++17
        reinterpret_cast<details::section_64*>(&header)->reserved3 = static_cast<uint32_t>(section.reserved3());
      }

      std::move(reinterpret_cast<uint8_t*>(&header),
                reinterpret_cast<uint8_t*>(&header) + sizeof(section_t),
                std::back_inserter(segment.original_data_));

    }
  }
  return ok();
} // build_segment


template<typename T>
ok_error_t Builder::build(DylibCommand* library) {
  LIEF_DEBUG("Build Dylib '{}'", library->name());

  const uint32_t raw_size = sizeof(details::dylib_command) + library->name().size() + 1;
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  if (library->original_data_.size() != size_needed ||
      library->size() != size_needed)
  {
    LIEF_WARN("Not enough spaces to rebuild {}. Size required: 0x{:x} vs 0x{:x}",
              library->name(),  library->original_data_.size(), size_needed);
  }

  details::dylib_command raw_cmd;
  std::memset(&raw_cmd, 0, sizeof(details::dylib_command));

  raw_cmd.cmd                         = static_cast<uint32_t>(library->command());
  raw_cmd.cmdsize                     = static_cast<uint32_t>(size_needed);
  raw_cmd.dylib.name                  = static_cast<uint32_t>(sizeof(details::dylib_command));
  raw_cmd.dylib.timestamp             = static_cast<uint32_t>(library->timestamp());
  raw_cmd.dylib.current_version       = static_cast<uint32_t>(DylibCommand::version2int(library->current_version()));
  raw_cmd.dylib.compatibility_version = static_cast<uint32_t>(DylibCommand::version2int(library->compatibility_version()));

  library->size_ = size_needed;
  library->original_data_.clear();

  // Write Header
  std::move(reinterpret_cast<uint8_t*>(&raw_cmd), reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(raw_cmd),
            std::back_inserter(library->original_data_));

  // Write String
  const std::string& libname = library->name();
  std::move(std::begin(libname), std::end(libname),
            std::back_inserter(library->original_data_));
  library->original_data_.push_back(0);
  library->original_data_.insert(std::end(library->original_data_), padding, 0);
  return ok();
}


template <typename T>
ok_error_t Builder::build(DylinkerCommand* linker) {

  LIEF_DEBUG("Build dylinker '{}'", linker->name());
  const uint32_t raw_size = sizeof(details::dylinker_command) + linker->name().size() + 1;
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  if (linker->original_data_.size() != size_needed ||
      linker->size() != size_needed)
  {
    LIEF_WARN("Not enough spaces to rebuild {}. Size required: 0x{:x} vs 0x{:x}",
              linker->name(),  linker->original_data_.size(), size_needed);
  }

  details::dylinker_command raw_cmd;
  std::memset(&raw_cmd, 0, sizeof(raw_cmd));

  raw_cmd.cmd     = static_cast<uint32_t>(linker->command());
  raw_cmd.cmdsize = static_cast<uint32_t>(size_needed);
  raw_cmd.name    = static_cast<uint32_t>(sizeof(details::dylinker_command));

  linker->size_ = size_needed;
  linker->original_data_.clear();

  // Write Header
  std::move(reinterpret_cast<uint8_t*>(&raw_cmd), reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(raw_cmd),
            std::back_inserter(linker->original_data_));

  // Write String
  const std::string& linkpath = linker->name();
  std::move(std::begin(linkpath), std::end(linkpath),
            std::back_inserter(linker->original_data_));

  linker->original_data_.push_back(0);
  linker->original_data_.insert(std::end(linker->original_data_), padding, 0);
  return ok();
}

template<class T>
ok_error_t Builder::build(VersionMin* version_min) {
  LIEF_DEBUG("Build '{}'", to_string(version_min->command()));
  const uint32_t raw_size = sizeof(details::version_min_command);
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  details::version_min_command raw_cmd;
  std::memset(&raw_cmd, 0, sizeof(details::version_min_command));

  const VersionMin::version_t& version = version_min->version();
  const VersionMin::version_t& sdk     = version_min->sdk();

  raw_cmd.cmd     = static_cast<uint32_t>(version_min->command());
  raw_cmd.cmdsize = static_cast<uint32_t>(version_min->size());
  raw_cmd.version = static_cast<uint32_t>(version[0] << 16 | version[1] << 8 | version[2]);
  raw_cmd.sdk     = static_cast<uint32_t>(sdk[0] << 16 | sdk[1] << 8 | sdk[2]);

  version_min->size_ = sizeof(details::version_min_command);
  version_min->original_data_.clear();
  std::move(reinterpret_cast<uint8_t*>(&raw_cmd),
            reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(details::version_min_command),
            std::back_inserter(version_min->original_data_));
  version_min->original_data_.insert(std::end(version_min->original_data_), padding, 0);
  return ok();
}


template<class T>
ok_error_t Builder::build(SourceVersion* source_version) {
  LIEF_DEBUG("Build '{}'", to_string(source_version->command()));
  const uint32_t raw_size = sizeof(details::source_version_command);
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  details::source_version_command raw_cmd;
  std::memset(&raw_cmd, 0, sizeof(details::source_version_command));

  const SourceVersion::version_t& version = source_version->version();
  raw_cmd.cmd     = static_cast<uint32_t>(source_version->command());
  raw_cmd.cmdsize = static_cast<uint32_t>(source_version->size());
  raw_cmd.version = static_cast<uint64_t>(
      static_cast<uint64_t>(version[0]) << 40 |
      static_cast<uint64_t>(version[1]) << 30 |
      static_cast<uint64_t>(version[2]) << 20 |
      static_cast<uint64_t>(version[3]) << 10 |
      static_cast<uint64_t>(version[4]));

  source_version->size_ = sizeof(details::source_version_command);
  source_version->original_data_.clear();
  std::move(reinterpret_cast<uint8_t*>(&raw_cmd),
            reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(details::source_version_command),
            std::back_inserter(source_version->original_data_));
  source_version->original_data_.insert(std::end(source_version->original_data_), padding, 0);
  return ok();
}


template<class T>
ok_error_t Builder::build(MainCommand* main_cmd) {
  LIEF_DEBUG("Build '{}'", to_string(main_cmd->command()));
  const uint32_t raw_size = sizeof(details::entry_point_command);
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  details::entry_point_command raw_cmd;
  std::memset(&raw_cmd, 0, sizeof(details::entry_point_command));

  raw_cmd.cmd       = static_cast<uint32_t>(main_cmd->command());
  raw_cmd.cmdsize   = static_cast<uint32_t>(main_cmd->size());
  raw_cmd.entryoff  = static_cast<uint64_t>(main_cmd->entrypoint());
  raw_cmd.stacksize = static_cast<uint64_t>(main_cmd->stack_size());

  main_cmd->size_ = sizeof(details::entry_point_command);
  main_cmd->original_data_.clear();
  std::move(reinterpret_cast<uint8_t*>(&raw_cmd),
            reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(details::entry_point_command),
            std::back_inserter(main_cmd->original_data_));
  main_cmd->original_data_.insert(std::end(main_cmd->original_data_), padding, 0);
  return ok();
}


template<class T>
ok_error_t Builder::build(DyldInfo* dyld_info) {
  LIEF_DEBUG("Build '{}'", to_string(dyld_info->command()));

  // /!\ Force to update relocation cache that is used by the following functions
  // TODO(romain): This looks like a hack
  binary_->relocations();
  {
    LIEF_SW_START(sw);
    dyld_info->update_export_trie();
    LIEF_SW_END("update_export_trie(): {}", sw.elapsed());
  }
  {
    LIEF_SW_START(sw);
    dyld_info->update_rebase_info();
    LIEF_SW_END("update_rebase_info(): {}", duration_cast<std::chrono::milliseconds>(sw.elapsed()));
  }
  {
    LIEF_SW_START(sw);
    dyld_info->update_binding_info();
    LIEF_SW_END("update_binding_info(): {}", duration_cast<std::chrono::seconds>(sw.elapsed()));
  }

  const uint32_t raw_size = sizeof(details::dyld_info_command);
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  details::dyld_info_command raw_cmd;
  std::memset(&raw_cmd, 0, sizeof(details::dyld_info_command));

  raw_cmd.cmd     = static_cast<uint32_t>(dyld_info->command());
  raw_cmd.cmdsize = static_cast<uint32_t>(dyld_info->size());

  std::tie(raw_cmd.rebase_off,    raw_cmd.rebase_size)    = dyld_info->rebase();
  std::tie(raw_cmd.bind_off,      raw_cmd.bind_size)      = dyld_info->bind();
  std::tie(raw_cmd.weak_bind_off, raw_cmd.weak_bind_size) = dyld_info->weak_bind();
  std::tie(raw_cmd.lazy_bind_off, raw_cmd.lazy_bind_size) = dyld_info->lazy_bind();
  std::tie(raw_cmd.export_off,    raw_cmd.export_size)    = dyld_info->export_info();

  dyld_info->size_ = sizeof(details::dyld_info_command);
  dyld_info->original_data_.clear();

  std::move(reinterpret_cast<uint8_t*>(&raw_cmd),
            reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(details::dyld_info_command),
            std::back_inserter(dyld_info->original_data_));

  dyld_info->original_data_.insert(std::end(dyld_info->original_data_), padding, 0);
  return ok();
}


template<class T>
ok_error_t Builder::build(FunctionStarts* function_starts) {
  LIEF_DEBUG("Build '{}'", to_string(function_starts->command()));

  std::vector<uint8_t> packed_functions;

  packed_functions.reserve(1024 * sizeof(uint64_t));

  uint64_t prev_address = 0;
  for (uint64_t address : function_starts->functions()) {

    uint64_t delta = address - prev_address;
    std::vector<uint8_t> encoded = LEB128::uencode(delta);

    std::move(std::begin(encoded), std::end(encoded),
              std::back_inserter(packed_functions));
    prev_address = address;
  }

  // Pad to pointer size
  size_t padding = align(packed_functions.size(), sizeof(typename T::uint)) -  packed_functions.size();
  packed_functions.insert(std::end(packed_functions), padding, 0);

  // Find the segment associated with LC_FUNCTION_STARTS
  SegmentCommand* segment = binary_->segment_from_offset(function_starts->data_offset());
  if (segment == nullptr) {
    LIEF_WARN("Can't find segment associated with function starts");
    return make_error_code(lief_errors::not_found);
  }
  span<uint8_t> content = segment->writable_content();
  uint64_t relative_offset = function_starts->data_offset() - segment->file_offset();
  if (relative_offset > content.size() || (relative_offset + packed_functions.size()) > content.size()) {
    LIEF_ERR("LC_FUNCTION_STARTS does not fit in the segment");
    return make_error_code(lief_errors::build_error);
  }
  std::move(std::begin(packed_functions), std::end(packed_functions),
            content.data() + relative_offset);


  // Write back the 'linkedit' structure
  const uint32_t raw_size = sizeof(details::linkedit_data_command);
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t struct_padding = size_needed - raw_size;

  details::linkedit_data_command raw_cmd;
  std::memset(&raw_cmd, 0, sizeof(details::linkedit_data_command));

  raw_cmd.cmd       = static_cast<uint32_t>(function_starts->command());
  raw_cmd.cmdsize   = static_cast<uint32_t>(function_starts->size());
  raw_cmd.dataoff   = static_cast<uint64_t>(function_starts->data_offset());
  raw_cmd.datasize  = static_cast<uint64_t>(function_starts->data_size());

  function_starts->size_ = sizeof(details::linkedit_data_command);
  function_starts->original_data_.clear();

  std::move(reinterpret_cast<uint8_t*>(&raw_cmd),
            reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(details::linkedit_data_command),
            std::back_inserter(function_starts->original_data_));
  function_starts->original_data_.insert(std::end(function_starts->original_data_), struct_padding, 0);
  return ok();
}

template<typename T, typename HANDLER>
std::vector<std::string> Builder::optimize(const HANDLER& container,
                                           std::function<std::string(const typename HANDLER::value_type)> getter,
                                           std::unordered_map<std::string, size_t> *of_map_p) {
  // TODO(romain): This function is also used in the ELF's builder -> move it in ian 'utils' part?
  std::set<std::string> string_table;
  std::vector<std::string> string_table_optimized;
  string_table_optimized.reserve(container.size());

  // reverse all symbol names and sort them so we can merge then in the linear time:
  // aaa, aadd, aaaa, cca, ca -> aaaa, aaa, acc, ac ddaa
  std::transform(std::begin(container), std::end(container),
                 std::inserter(string_table, std::end(string_table)), getter);

  for (const auto &val: string_table) {
    string_table_optimized.emplace_back(val);
    std::reverse(std::begin(string_table_optimized.back()), std::end(string_table_optimized.back()));
  }

  std::sort(std::begin(string_table_optimized), std::end(string_table_optimized),
      [] (const std::string& lhs, const std::string& rhs) {
          bool ret = false;
          if (lhs.size() > rhs.size()) {
              auto res = lhs.compare(0, rhs.size(), rhs);
              ret = (res <= 0);
          } else {
              auto res = rhs.compare(0, lhs.size(), lhs);
              ret = (res > 0);
          }
          return ret;
  });

  // as all elements that can be merged are adjacent we can just go through the list once
  // and memorize one we merged to calculate the offsets later
  std::unordered_map<std::string, std::string> merged_map;
  size_t to_set_idx = 0, cur_elm_idx = 1;
  for (; cur_elm_idx < string_table_optimized.size(); ++cur_elm_idx) {
      auto &cur_elm = string_table_optimized[cur_elm_idx];
      auto &to_set_elm = string_table_optimized[to_set_idx];
      if (to_set_elm.size() >= cur_elm.size()) {
          auto ret = to_set_elm.compare(0, cur_elm.size(), cur_elm);
          if (ret == 0) {
              // when memorizing reverse back symbol names
              std::string rev_cur_elm = cur_elm;
              std::string rev_to_set_elm = to_set_elm;
              std::reverse(std::begin(rev_cur_elm), std::end(rev_cur_elm));
              std::reverse(std::begin(rev_to_set_elm), std::end(rev_to_set_elm));
              merged_map[rev_cur_elm] = rev_to_set_elm;
              continue;
          }
      }
      ++to_set_idx;
      std::swap(string_table_optimized[to_set_idx], cur_elm);
  }
  // if the first one is empty
  if (string_table_optimized[0].empty()) {
    std::swap(string_table_optimized[0], string_table_optimized[to_set_idx]);
    --to_set_idx;
  }
  string_table_optimized.resize(to_set_idx + 1);

  //reverse symbols back and sort them again
  for (auto &val: string_table_optimized) {
      std::reverse(std::begin(val), std::end(val));
  }
  std::sort(std::begin(string_table_optimized), std::end(string_table_optimized));

  if (of_map_p) {
    std::unordered_map<std::string, size_t> offset_map;
    offset_map[""] = 0;
    size_t offset_counter = 1;
    for (const auto &v : string_table_optimized) {
        offset_map[v] = offset_counter;
        offset_counter += v.size() + 1;
    }
    for (const auto &kv : merged_map) {
        offset_map[kv.first] = offset_map[kv.second] + (kv.second.size() - kv.first.size());
    }
    *of_map_p = std::move(offset_map);
  }

  return string_table_optimized;
}



template<class T>
ok_error_t Builder::build(SymbolCommand* symbol_command) {

  //template <typename A>
  //void SymbolTableAtom<A>::encode()
  //{
  //  // Note: We lay out the symbol table so that the strings for the stabs (local) symbols are at the
  //  // end of the string pool.  The stabs strings are not used when calculated the UUID for the image.
  //  // If the stabs strings were not last, the string offsets for all other symbols may very which would alter the UUID.
  //
  //  // reserve space for local symbols
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

  details::symtab_command symtab;
  std::memset(&symtab, 0, sizeof(details::symtab_command));


  std::vector<Symbol*> symbols;
  symbols.reserve(binary_->symbols().size());


  // 1. Fill the string table
  // -------------------------------------
  for (Symbol& s : binary_->symbols()) {
    if (s.origin() == SYMBOL_ORIGINS::SYM_ORIGIN_LC_SYMTAB) {
      symbols.push_back(&s);
    }
  }

  std::unordered_map<std::string, size_t> offset_name_map;
  std::vector<std::string> string_table_opt = optimize<Symbol, decltype(symbols)>(
                                                symbols, [] (const Symbol* sym) { return sym->name(); },
                                                &offset_name_map);
  // 0 index is reserved
  vector_iostream raw_symbol_names;
  raw_symbol_names.write<uint8_t>(0);
  for (const std::string& name : string_table_opt) {
    raw_symbol_names.write(name);
  }

  // If the table is smaller than th original one, fill with 0
  if (raw_symbol_names.size() < symbol_command->strings_size()) {
    const size_t padding = symbol_command->strings_size() - raw_symbol_names.size();
    raw_symbol_names.write(padding, 0);
  }
  raw_symbol_names.align(sizeof(uint));


  if (raw_symbol_names.size() > symbol_command->strings_size()) {
    LIEF_WARN("Larger symbol names size is not supported yet");
    return make_error_code(lief_errors::not_supported);
  }

  // Update the segment that contains the string table
  SegmentCommand* segment = binary_->segment_from_offset(symbol_command->strings_offset());
  if (segment == nullptr) {
    LIEF_WARN("Can't find segment associated with string table");
    return make_error_code(lief_errors::not_found);
  }

  std::vector<uint8_t> symname_data = raw_symbol_names.raw();
  span<uint8_t> content = segment->writable_content();
  uint64_t relative_offset = symbol_command->strings_offset() - segment->file_offset();
  if (relative_offset > content.size() || (relative_offset + symname_data.size()) > content.size()) {
    LIEF_WARN("Symbols names don't fit in the segment");
    return make_error_code(lief_errors::build_error);
  }
  std::move(std::begin(symname_data), std::end(symname_data), content.data() + relative_offset);

  // 2. Fill the n_list table
  // -------------------------------------
  vector_iostream nlist_table;
  nlist_table.reserve(symbols.size() * sizeof(nlist_t));
  for (Symbol* sym : symbols) {
    const std::string& name = sym->name();
    const auto it_name = offset_name_map.find(name);

    if (it_name == std::end(offset_name_map)) {
      LIEF_WARN("Can't find name offset for symbol {}", sym->name());
      continue;
    }

    nlist_t nl;
    nl.n_strx  = static_cast<uint32_t>(it_name->second);
    nl.n_type  = static_cast<uint8_t>(sym->type());
    nl.n_sect  = static_cast<uint32_t>(sym->numberof_sections());
    nl.n_desc  = static_cast<uint16_t>(sym->description());
    nl.n_value = static_cast<uint>(sym->value());

    nlist_table.write(nl);
  }

  if (nlist_table.size() != symbol_command->numberof_symbols() * sizeof(nlist_t)) {
    LIEF_WARN("nlist_table.size() is not consistent");
    return make_error_code(lief_errors::build_error);
  }

  segment = binary_->segment_from_offset(symbol_command->symbol_offset());
  if (segment == nullptr) {
    LIEF_WARN("Can't find segment associated with symbol table");
    return make_error_code(lief_errors::not_found);
  }

  content = segment->writable_content();
  relative_offset = symbol_command->symbol_offset() - segment->file_offset();
  std::vector<uint8_t> raw_nlist_table = nlist_table.raw();

  if (relative_offset > content.size() || (relative_offset + raw_nlist_table.size()) > content.size()) {
    LIEF_WARN("Symbols nlist don't fit in the segment");
    return make_error_code(lief_errors::build_error);
  }


  std::move(std::begin(raw_nlist_table), std::end(raw_nlist_table),
            content.data() + relative_offset);

  // 3. Fill the Header

  symtab.cmd     = static_cast<uint32_t>(symbol_command->command());
  symtab.cmdsize = static_cast<uint32_t>(symbol_command->size());
  symtab.symoff  = static_cast<uint32_t>(symbol_command->symbol_offset());    // **Usually** After the header
  symtab.nsyms   = static_cast<uint32_t>(symbol_command->numberof_symbols());
  symtab.stroff  = static_cast<uint32_t>(symbol_command->strings_offset());   // **Usually** After nlist table


  // TODO: Improve
  // Update linkedit segment
  SegmentCommand& linkedit = *binary_->get_segment("__LINKEDIT");
  size_t delta = linkedit.file_offset() + linkedit.file_size();
  delta = delta - (symbol_command->strings_offset() + symbol_command->strings_size());
  symtab.strsize = static_cast<uint32_t>(symbol_command->strings_size() + delta);

  symbol_command->original_data_.clear();
  symbol_command->original_data_.reserve(sizeof(details::symtab_command));

  std::move(
      reinterpret_cast<const uint8_t*>(&symtab),
      reinterpret_cast<const uint8_t*>(&symtab) + sizeof(details::symtab_command),
      std::back_inserter(symbol_command->original_data_)
  );
  return ok();
}


template<class T>
ok_error_t Builder::build(DynamicSymbolCommand* symbol_command) {
  details::dysymtab_command rawcmd;
  std::memset(&rawcmd, 0, sizeof(details::dysymtab_command));

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

  symbol_command->original_data_.clear();
  symbol_command->original_data_.reserve(sizeof(details::dysymtab_command));

  std::move(reinterpret_cast<const uint8_t*>(&rawcmd),
            reinterpret_cast<const uint8_t*>(&rawcmd) + sizeof(details::dysymtab_command),
            std::back_inserter(symbol_command->original_data_)
  );
  return ok();
}

template<class T>
ok_error_t Builder::build(DataInCode* datacode) {
  LIEF_DEBUG("Build '{}'", to_string(datacode->command()));

  details::linkedit_data_command raw_cmd;
  std::memset(&raw_cmd, 0, sizeof(details::linkedit_data_command));

  raw_cmd.cmd       = static_cast<uint32_t>(datacode->command());
  raw_cmd.cmdsize   = static_cast<uint32_t>(datacode->size());
  raw_cmd.dataoff   = static_cast<uint64_t>(datacode->data_offset());
  raw_cmd.datasize  = static_cast<uint64_t>(datacode->data_size());

  datacode->size_ = sizeof(details::linkedit_data_command);
  datacode->original_data_.clear();

  std::move(reinterpret_cast<uint8_t*>(&raw_cmd),
            reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(details::linkedit_data_command),
            std::back_inserter(datacode->original_data_));
  return ok();
}

template<class T>
ok_error_t Builder::build(CodeSignature* code_signature) {
  LIEF_DEBUG("Build '{}'", to_string(code_signature->command()));

  details::linkedit_data_command raw_cmd;
  std::memset(&raw_cmd, 0, sizeof(details::linkedit_data_command));

  raw_cmd.cmd       = static_cast<uint32_t>(code_signature->command());
  raw_cmd.cmdsize   = static_cast<uint32_t>(code_signature->size());
  raw_cmd.dataoff   = static_cast<uint64_t>(code_signature->data_offset());
  raw_cmd.datasize  = static_cast<uint64_t>(code_signature->data_size());

  code_signature->size_ = sizeof(details::linkedit_data_command);
  code_signature->original_data_.clear();

  std::move(reinterpret_cast<uint8_t*>(&raw_cmd),
            reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(details::linkedit_data_command),
            std::back_inserter(code_signature->original_data_));
  return ok();
}

template<class T>
ok_error_t Builder::build(SegmentSplitInfo* ssi) {
  LIEF_DEBUG("Build '{}'", to_string(ssi->command()));

  details::linkedit_data_command raw_cmd;
  std::memset(&raw_cmd, 0, sizeof(details::linkedit_data_command));

  raw_cmd.cmd       = static_cast<uint32_t>(ssi->command());
  raw_cmd.cmdsize   = static_cast<uint32_t>(ssi->size());
  raw_cmd.dataoff   = static_cast<uint64_t>(ssi->data_offset());
  raw_cmd.datasize  = static_cast<uint64_t>(ssi->data_size());

  ssi->size_ = sizeof(details::linkedit_data_command);
  ssi->original_data_.clear();

  std::move(reinterpret_cast<uint8_t*>(&raw_cmd),
            reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(details::linkedit_data_command),
            std::back_inserter(ssi->original_data_));
  return ok();
}

template<class T>
ok_error_t Builder::build(SubFramework* sf) {
  details::sub_framework_command raw_cmd;
  std::memset(&raw_cmd, 0, sizeof(details::sub_framework_command));

  const uint32_t raw_size = sizeof(details::sub_framework_command) + sf->umbrella().size() + 1;
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  if (sf->original_data_.size() != size_needed ||
      sf->size() != size_needed) {

    LIEF_WARN("Not enough spaces to rebuild {}. Size required: 0x{:x} vs 0x{:x}",
              sf->umbrella(),  sf->original_data_.size(), size_needed);
  }

  raw_cmd.cmd      = static_cast<uint32_t>(sf->command());
  raw_cmd.cmdsize  = static_cast<uint32_t>(size_needed);
  raw_cmd.umbrella = static_cast<uint32_t>(sizeof(details::sub_framework_command));

  sf->size_ = size_needed;
  sf->original_data_.clear();

  // Write Header
  std::move(reinterpret_cast<uint8_t*>(&raw_cmd),
            reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(raw_cmd),
            std::back_inserter(sf->original_data_));

  // Write String
  const std::string& um = sf->umbrella();
  std::move(std::begin(um), std::end(um), std::back_inserter(sf->original_data_));
  sf->original_data_.push_back(0);
  sf->original_data_.insert(std::end(sf->original_data_), padding, 0);
  return ok();
}

template<class T>
ok_error_t Builder::build(DyldEnvironment* de) {
  details::dylinker_command raw_cmd;
  std::memset(&raw_cmd, 0, sizeof(details::dylinker_command));

  const uint32_t raw_size = sizeof(details::dylinker_command) + de->value().size() + 1;
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  if (de->original_data_.size() != size_needed ||
      de->size() != size_needed) {
    LIEF_WARN("Not enough spaces to rebuild {}. Size required: 0x{:x} vs 0x{:x}",
              de->value(),  de->original_data_.size(), size_needed);
  }

  raw_cmd.cmd      = static_cast<uint32_t>(de->command());
  raw_cmd.cmdsize  = static_cast<uint32_t>(size_needed);
  raw_cmd.name     = static_cast<uint32_t>(sizeof(details::dylinker_command));

  de->size_ = size_needed;
  de->original_data_.clear();

  // Write Header
  std::move(reinterpret_cast<uint8_t*>(&raw_cmd),
            reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(raw_cmd),
            std::back_inserter(de->original_data_));

  // Write String
  const std::string& value = de->value();
  std::move(std::begin(value), std::end(value), std::back_inserter(de->original_data_));

  de->original_data_.push_back(0);
  de->original_data_.insert(std::end(de->original_data_), padding, 0);
  return ok();
}

template<class T>
ok_error_t Builder::build(ThreadCommand* tc) {
  details::thread_command raw_cmd;
  std::memset(&raw_cmd, 0, sizeof(details::thread_command));

  const std::vector<uint8_t>& state = tc->state();

  const uint32_t raw_size = sizeof(details::thread_command) + state.size();
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  if (tc->original_data_.size() != size_needed || tc->size() != size_needed) {
    LIEF_WARN("Not enough spaces to rebuild 'ThreadCommand'. Size required: 0x{:x} vs 0x{:x}",
              tc->original_data_.size(), size_needed);
  }

  const uint32_t state_size_needed = tc->count() * sizeof(uint32_t);
  if (state.size() < state_size_needed) {

    LIEF_WARN("Not enough spaces to rebuild 'ThreadCommand'. Size required: 0x{:x} vs 0x{:x}",
              state.size(), state_size_needed);
  }


  raw_cmd.cmd      = static_cast<uint32_t>(tc->command());
  raw_cmd.cmdsize  = static_cast<uint32_t>(size_needed);
  raw_cmd.flavor   = static_cast<uint32_t>(tc->flavor());
  raw_cmd.count    = static_cast<uint32_t>(tc->count());

  tc->size_ = size_needed;
  tc->original_data_.clear();

  // Write Header
  std::move(reinterpret_cast<uint8_t*>(&raw_cmd),
            reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(raw_cmd),
            std::back_inserter(tc->original_data_));

  // Write state
  std::move(std::begin(state), std::end(state), std::back_inserter(tc->original_data_));

  tc->original_data_.push_back(0);
  tc->original_data_.insert(std::end(tc->original_data_), padding, 0);
  return ok();
}


template<class T>
ok_error_t Builder::build(BuildVersion* bv) {
  details::build_version_command raw_cmd;
  std::memset(&raw_cmd, 0, sizeof(details::build_version_command));

  const BuildVersion::tools_list_t& tools = bv->tools();

  const uint32_t raw_size    = sizeof(details::build_version_command) + tools.size() * sizeof(details::build_tool_version);
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding     = size_needed - raw_size;

  if (bv->original_data_.size() != size_needed || bv->size() != size_needed) {
    LIEF_WARN("Not enough spaces to rebuild 'BuildVersion'. Size required: 0x{:x} vs 0x{:x}",
               bv->original_data_.size(), size_needed);
  }

  const BuildVersion::version_t& minos    = bv->minos();
  const BuildVersion::version_t& sdk      = bv->sdk();

  raw_cmd.cmd      = static_cast<uint32_t>(bv->command());
  raw_cmd.cmdsize  = static_cast<uint32_t>(size_needed);

  raw_cmd.minos    = static_cast<uint32_t>(minos[0] << 16 | minos[1] << 8 | minos[2]);
  raw_cmd.sdk      = static_cast<uint32_t>(sdk[0] << 16 | sdk[1] << 8 | sdk[2]);
  raw_cmd.platform = static_cast<uint32_t>(bv->platform());
  raw_cmd.ntools   = tools.size();
  //raw_cmd.name     = static_cast<uint32_t>(sizeof(build_version_command));
  std::vector<uint8_t> raw_tools(raw_cmd.ntools * sizeof(details::build_tool_version), 0);
  auto* tools_array = reinterpret_cast<details::build_tool_version*>(raw_tools.data());
  for (size_t i = 0; i < tools.size(); ++i) {
    BuildToolVersion::version_t version = tools[i].version();
    tools_array[i].tool    = static_cast<uint32_t>(tools[i].tool());
    tools_array[i].version = static_cast<uint32_t>(version[0] << 16 | version[1] << 8 | version[2]);
  }

  bv->size_ = size_needed;
  bv->original_data_.clear();

  // Write Header
  std::move(reinterpret_cast<uint8_t*>(&raw_cmd), reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(raw_cmd),
            std::back_inserter(bv->original_data_));

  std::move(std::begin(raw_tools), std::end(raw_tools), std::back_inserter(bv->original_data_));

  bv->original_data_.insert(std::end(bv->original_data_), padding, 0);
  return ok();
}



}
}
