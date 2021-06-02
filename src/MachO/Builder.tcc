/* Copyright 2017 - 2021 R. Thomas
 * Copyright 2017 - 2021 Quarkslab
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
#include "LIEF/MachO/Structures.hpp"
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

namespace LIEF {
namespace MachO {


template<typename T>
void Builder::build_segments(void) {
  using section_t  = typename T::section;
  using segment_t  = typename T::segment_command;
  using uint__     = typename T::uint;

  LIEF_DEBUG("[+] Rebuilding segments");
  Binary* binary =  this->binaries_.back();
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
      throw LIEF::builder_error("content.size() != segment.file_size()");
    }

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
      const std::string& sec_name = section.name();
      const std::string& segment_name = segment.name();
      LIEF_DEBUG("{}", section);
      section_t header;
      std::memset(&header, 0, sizeof(header));

      const uint32_t segname_length = std::min<uint32_t>(segment_name.size() + 1,
                                                         sizeof(header.segname));
      std::copy(segment_name.c_str(), segment_name.c_str() + segname_length,
                std::begin(header.segname));

      const uint32_t secname_length = std::min<uint32_t>(sec_name.size() + 1,
                                                         sizeof(header.sectname));
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
void Builder::build(DylibCommand* library) {
  LIEF_DEBUG("Build Dylib '{}'", library->name());

  const uint32_t raw_size = sizeof(dylib_command) + library->name().size() + 1;
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  if (library->originalData_.size() != size_needed or
      library->size() != size_needed) {
    LIEF_WARN("Not enough spaces to rebuild {}. Size required: 0x{:x} vs 0x{:x}",
        library->name(),  library->originalData_.size(), size_needed);
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

  LIEF_DEBUG("Build dylinker '{}'", linker->name());
  const uint32_t raw_size = sizeof(dylinker_command) + linker->name().size() + 1;
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  if (linker->originalData_.size() != size_needed or
      linker->size() != size_needed) {

    LIEF_WARN("Not enough spaces to rebuild {}. Size required: 0x{:x} vs 0x{:x}",
        linker->name(),  linker->originalData_.size(), size_needed);
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
  LIEF_DEBUG("Build '{}'", to_string(version_min->command()));
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
  LIEF_DEBUG("Build '{}'", to_string(source_version->command()));
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
  LIEF_DEBUG("Build '{}'", to_string(main_cmd->command()));
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
  LIEF_DEBUG("Build '{}'", to_string(dyld_info->command()));

  // /!\ Force to update relocation cache that is used by the following functions
  // TODO(romain): This looks like a hack
  this->binary_->relocations();

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
      reinterpret_cast<uint8_t*>(&raw_cmd), reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(dyld_info_command),
      std::back_inserter(dyld_info->originalData_));
  dyld_info->originalData_.insert(std::end(dyld_info->originalData_), padding, 0);


  // Write Back Content

  // Rebase opcodes
  // ==============
  {
    const buffer_t& rebase_opcodes = dyld_info->rebase_opcodes();
    if (rebase_opcodes.size() != raw_cmd.rebase_size) {
      LIEF_WARN("Rebase opcodes size is different from metadata");
    }

    SegmentCommand* rebase_segment = this->binary_->segment_from_offset(raw_cmd.rebase_off);
    if (rebase_segment == nullptr) {
      LIEF_WARN("Rebease segment is null");
    }
    else {
      uint64_t relative_offset = raw_cmd.rebase_off - rebase_segment->file_offset();

      std::vector<uint8_t> content = rebase_segment->content();

      std::move(
          std::begin(rebase_opcodes), std::end(rebase_opcodes),
          content.data() + relative_offset);
      rebase_segment->content(std::move(content));
    }
  }

  // Bind opcodes
  // ============
  {
    const buffer_t& bind_opcodes = dyld_info->bind_opcodes();
    if (bind_opcodes.size() != raw_cmd.bind_size) {
      LIEF_WARN("Bind opcodes size is different from metadata");
    }

    SegmentCommand* bind_segment = this->binary_->segment_from_offset(raw_cmd.bind_off);
    if (bind_segment == nullptr) {
      LIEF_WARN("Bind segment is null");
    }
    else {
      uint64_t relative_offset = raw_cmd.bind_off - bind_segment->file_offset();
      std::vector<uint8_t> content = bind_segment->content();
      std::move(
          std::begin(bind_opcodes), std::end(bind_opcodes),
          content.data() + relative_offset);
      bind_segment->content(std::move(content));
    }
  }


  // Weak Bind opcodes
  // =================
  {
    const buffer_t& weak_bind_opcodes = dyld_info->weak_bind_opcodes();
    if (weak_bind_opcodes.size() != raw_cmd.weak_bind_size) {
      LIEF_WARN("Weak Bind opcodes size is different from metadata");
    }

    SegmentCommand* weak_bind_segment = this->binary_->segment_from_offset(raw_cmd.weak_bind_off);
    if (weak_bind_segment == nullptr) {
      LIEF_WARN("Weak bind segment is null");
    }
    else {
      uint64_t relative_offset = raw_cmd.weak_bind_off - weak_bind_segment->file_offset();
      std::vector<uint8_t> content = weak_bind_segment->content();
      std::move(
          std::begin(weak_bind_opcodes), std::end(weak_bind_opcodes),
          content.data() + relative_offset);
      weak_bind_segment->content(std::move(content));
    }
  }


  // Lazy Bind opcodes
  // =================
  {
    const buffer_t& lazy_bind_opcodes = dyld_info->lazy_bind_opcodes();
    if (lazy_bind_opcodes.size() != raw_cmd.lazy_bind_size) {
      LIEF_WARN("Lazy Bind opcodes size is different from metadata");
    }

    SegmentCommand* lazy_bind_segment = this->binary_->segment_from_offset(raw_cmd.lazy_bind_off);
    if (lazy_bind_segment == nullptr) {
      LIEF_WARN("Lazy bind segment is null");
    }
    else {
      uint64_t relative_offset = raw_cmd.lazy_bind_off - lazy_bind_segment->file_offset();
      std::vector<uint8_t> content = lazy_bind_segment->content();
      std::move(
          std::begin(lazy_bind_opcodes), std::end(lazy_bind_opcodes),
          content.data() + relative_offset);
      lazy_bind_segment->content(std::move(content));
    }
  }


  // Export trie
  // ===========
  {
    const buffer_t& export_trie = dyld_info->export_trie();
    if (export_trie.size() != raw_cmd.export_size) {
      LIEF_WARN("Export trie size is different from metadata");
    }

    SegmentCommand* export_segment = this->binary_->segment_from_offset(raw_cmd.export_off);
    if (export_segment == nullptr) {
      LIEF_WARN("Export segment is null");
    } else {
      uint64_t relative_offset = raw_cmd.export_off - export_segment->file_offset();
      std::vector<uint8_t> content = export_segment->content();
      std::move(
          std::begin(export_trie), std::end(export_trie),
          content.data() + relative_offset);
      export_segment->content(std::move(content));
    }
  }


}


template<class T>
void Builder::build(FunctionStarts* function_starts) {
  LIEF_DEBUG("Build '{}'", to_string(function_starts->command()));

  std::vector<uint8_t> packed_functions;

  packed_functions.reserve(1024 * sizeof(uint64_t));

  uint64_t prev_address = 0;
  for (uint64_t address : function_starts->functions()) {

    uint64_t delta = address - prev_address;
    std::vector<uint8_t> encoded = LEB128::uencode(delta);

    std::move(
        std::begin(encoded), std::end(encoded),
        std::back_inserter(packed_functions));
    prev_address = address;
  }

  // Pad to pointer size
  size_t padding = align(packed_functions.size(), sizeof(typename T::uint)) -  packed_functions.size();
  packed_functions.insert(std::end(packed_functions), padding, 0);

  // Find the segment associated with LC_FUNCTION_STARTS
  SegmentCommand* segment = this->binary_->segment_from_offset(function_starts->data_offset());
  if (segment == nullptr) {
    LIEF_WARN("Can't find segment associated with function starts");
    return;
  }
  std::vector<uint8_t> content = segment->content();
  uint64_t relative_offset = function_starts->data_offset() - segment->file_offset();
  std::move(
      std::begin(packed_functions), std::end(packed_functions),
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

template<typename T, typename HANDLER>
std::vector<std::string> Builder::optimize(const HANDLER& container,
                                           std::function<std::string(const typename HANDLER::value_type)> getter,
                                           std::unordered_map<std::string, size_t> *of_map_p) {
  // TODO(romain): This function is also used in the ELF's builder -> move it in the 'utils' part

  std::set<std::string> string_table;
  std::vector<std::string> string_table_optimized;
  string_table_optimized.reserve(container.size());

  // reverse all symbol names and sort them so we can merge then in the linear time:
  // aaa, aadd, aaaa, cca, ca -> aaaa, aaa, acc, ac ddaa
  std::transform(
    std::begin(container), std::end(container),
    std::inserter(string_table, std::end(string_table)),
    getter);

  for (auto &val: string_table) {
    string_table_optimized.emplace_back(std::move(val));
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
  if (string_table_optimized[0].size() == 0) {
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
void Builder::build(SymbolCommand* symbol_command) {

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

  symtab_command symtab;


  std::vector<Symbol*> symbols;
  symbols.reserve(this->binary_->symbols().size());


  // 1. Fill the string table
  // -------------------------------------
  for (Symbol& s : this->binary_->symbols()) {
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
  for (std::string name : string_table_opt) {
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
    return;
  }

  // Update the segment that contains the string table
  SegmentCommand* segment = this->binary_->segment_from_offset(symbol_command->strings_offset());
  if (segment == nullptr) {
    LIEF_WARN("Can't find segment associated with string table");
    return;
  }

  std::vector<uint8_t> symname_data = raw_symbol_names.raw();
  std::vector<uint8_t> content = segment->content();
  uint64_t relative_offset = symbol_command->strings_offset() - segment->file_offset();
  std::move(std::begin(symname_data), std::end(symname_data), content.data() + relative_offset);
  segment->content(std::move(content));

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
    return;
  }

  segment = this->binary_->segment_from_offset(symbol_command->symbol_offset());
  if (segment == nullptr) {
    LIEF_WARN("Can't find segment associated with symbol table");
    return;
  }

  content = segment->content();
  relative_offset = symbol_command->symbol_offset() - segment->file_offset();
  std::vector<uint8_t> raw_nlist_table = nlist_table.raw();
  std::move(std::begin(raw_nlist_table), std::end(raw_nlist_table),
            content.data() + relative_offset);
  segment->content(std::move(content));

  // 3. Fill the Header
  std::memset(&symtab, 0, sizeof(symtab_command));

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
  LIEF_DEBUG("Build '{}'", to_string(datacode->command()));

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
  LIEF_DEBUG("Build '{}'", to_string(code_signature->command()));

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
  LIEF_DEBUG("Build '{}'", to_string(ssi->command()));

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

    LIEF_WARN("Not enough spaces to rebuild {}. Size required: 0x{:x} vs 0x{:x}",
        sf->umbrella(),  sf->originalData_.size(), size_needed);
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
    LIEF_WARN("Not enough spaces to rebuild {}. Size required: 0x{:x} vs 0x{:x}",
        de->value(),  de->originalData_.size(), size_needed);
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
void Builder::build(ThreadCommand* tc) {
  thread_command raw_cmd;

  const std::vector<uint8_t>& state = tc->state();

  const uint32_t raw_size = sizeof(thread_command) + state.size();
  const uint32_t size_needed = align(raw_size, sizeof(typename T::uint));
  const uint32_t padding = size_needed - raw_size;

  if (tc->originalData_.size() != size_needed or
      tc->size() != size_needed) {
    LIEF_WARN("Not enough spaces to rebuild 'ThreadCommand'. Size required: 0x{:x} vs 0x{:x}",
        tc->originalData_.size(), size_needed);
  }

  const uint32_t state_size_needed = tc->count() * sizeof(uint32_t);
  if (state.size() < state_size_needed) {

    LIEF_WARN("Not enough spaces to rebuild 'ThreadCommand'. Size required: 0x{:x} vs 0x{:x}",
        state.size(), state_size_needed);
  }

  std::fill(
    reinterpret_cast<uint8_t*>(&raw_cmd),
    reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(thread_command),
    0);

  raw_cmd.cmd      = static_cast<uint32_t>(tc->command());
  raw_cmd.cmdsize  = static_cast<uint32_t>(size_needed);
  raw_cmd.flavor   = static_cast<uint32_t>(tc->flavor());
  raw_cmd.count    = static_cast<uint32_t>(tc->count());

  tc->size_ = size_needed;
  tc->originalData_.clear();

  // Write Header
  std::move(
    reinterpret_cast<uint8_t*>(&raw_cmd),
    reinterpret_cast<uint8_t*>(&raw_cmd) + sizeof(raw_cmd),
    std::back_inserter(tc->originalData_));

  // Write state
  std::move(
    std::begin(state),
    std::end(state),
    std::back_inserter(tc->originalData_));
  tc->originalData_.push_back(0);
  tc->originalData_.insert(std::end(tc->originalData_), padding, 0);
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
    LIEF_WARN("Not enough spaces to rebuild 'BuildVersion'. Size required: 0x{:x} vs 0x{:x}",
        bv->originalData_.size(), size_needed);
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
