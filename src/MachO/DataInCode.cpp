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

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/DataInCode.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

DataInCode::DataInCode() = default;
DataInCode& DataInCode::operator=(const DataInCode&) = default;
DataInCode::DataInCode(const DataInCode&) = default;
DataInCode::~DataInCode() = default;

DataInCode::DataInCode(const details::linkedit_data_command& cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd.cmd), cmd.cmdsize},
  data_offset_{cmd.dataoff},
  data_size_{cmd.datasize}
{}

DataInCode* DataInCode::clone() const {
  return new DataInCode(*this);
}

uint32_t DataInCode::data_offset() const {
  return data_offset_;
}

uint32_t DataInCode::data_size() const {
  return data_size_;
}

void DataInCode::data_offset(uint32_t offset) {
  data_offset_ = offset;
}

void DataInCode::data_size(uint32_t size) {
  data_size_ = size;
}


DataInCode& DataInCode::add(const DataCodeEntry& entry) {
  entries_.push_back(entry);
  return *this;
}


DataInCode::it_const_entries DataInCode::entries() const {
  return entries_;
}

DataInCode::it_entries DataInCode::entries() {
  return entries_;
}


void DataInCode::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool DataInCode::operator==(const DataInCode& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DataInCode::operator!=(const DataInCode& rhs) const {
  return !(*this == rhs);
}

bool DataInCode::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_DATA_IN_CODE;
}


std::ostream& DataInCode::print(std::ostream& os) const {
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
