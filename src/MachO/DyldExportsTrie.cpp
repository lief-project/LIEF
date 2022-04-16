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
#include <numeric>
#include <iomanip>

#include "LIEF/BinaryStream/SpanStream.hpp"

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/DyldExportsTrie.hpp"
#include "LIEF/MachO/ExportInfo.hpp"

#include "MachO/Structures.hpp"
#include "MachO/exports_trie.hpp"

namespace LIEF {
namespace MachO {
DyldExportsTrie::DyldExportsTrie() = default;
DyldExportsTrie::~DyldExportsTrie() = default;
DyldExportsTrie::DyldExportsTrie(const DyldExportsTrie& other) :
  data_offset_{other.data_offset_},
  data_size_{other.data_size_}
{
  /* Do not copy export info */
}

DyldExportsTrie& DyldExportsTrie::operator=(DyldExportsTrie other) {
  swap(other);
  return *this;
}

DyldExportsTrie::DyldExportsTrie(const details::linkedit_data_command& cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd.cmd), cmd.cmdsize},
  data_offset_{cmd.dataoff},
  data_size_{cmd.datasize}
{}


void DyldExportsTrie::swap(DyldExportsTrie& other) {
  LoadCommand::swap(other);
  std::swap(data_offset_, other.data_offset_);
  std::swap(data_size_,   other.data_size_);
  std::swap(content_,     other.content_);
  std::swap(export_info_, other.export_info_);
}

DyldExportsTrie* DyldExportsTrie::clone() const {
  return new DyldExportsTrie(*this);
}


uint32_t DyldExportsTrie::data_offset() const {
  return data_offset_;
}

uint32_t DyldExportsTrie::data_size() const {
  return data_size_;
}

void DyldExportsTrie::data_offset(uint32_t offset) {
  data_offset_ = offset;
}

void DyldExportsTrie::data_size(uint32_t size) {
  data_size_ = size;
}

void DyldExportsTrie::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

DyldExportsTrie::it_export_info DyldExportsTrie::exports() {
  return export_info_;
}

DyldExportsTrie::it_const_export_info DyldExportsTrie::exports() const {
  return export_info_;
}


void DyldExportsTrie::add(std::unique_ptr<ExportInfo> info) {
  export_info_.push_back(std::move(info));
}


std::string DyldExportsTrie::show_export_trie() const {
  std::ostringstream output;

  SpanStream stream = content_;
  show_trie(output, "", stream, 0, content_.size(), "");

  return output.str();
}


bool DyldExportsTrie::operator==(const DyldExportsTrie& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DyldExportsTrie::operator!=(const DyldExportsTrie& rhs) const {
  return !(*this == rhs);
}

bool DyldExportsTrie::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_DYLD_EXPORTS_TRIE;
}


std::ostream& DyldExportsTrie::print(std::ostream& os) const {
  LoadCommand::print(os);
  os << std::left;
  os << std::endl;
  os << "Data location:" << std::endl;
  os << std::setw(8) << "Offset" << ": 0x" << data_offset() << std::endl;
  os << std::setw(8) << "Size"   << ": 0x" << data_size()   << std::endl;
  return os;
}

}
}
