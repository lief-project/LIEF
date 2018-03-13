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
#include <numeric>
#include <iomanip>

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/FunctionStarts.hpp"

namespace LIEF {
namespace MachO {

FunctionStarts::FunctionStarts(void) = default;
FunctionStarts& FunctionStarts::operator=(const FunctionStarts&) = default;
FunctionStarts::FunctionStarts(const FunctionStarts&) = default;
FunctionStarts::~FunctionStarts(void) = default;

FunctionStarts::FunctionStarts(const linkedit_data_command *cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd->cmd), cmd->cmdsize},
  data_offset_{cmd->dataoff},
  data_size_{cmd->datasize}
{}

uint32_t FunctionStarts::data_offset(void) const {
  return this->data_offset_;
}

uint32_t FunctionStarts::data_size(void) const {
  return this->data_size_;
}

void FunctionStarts::data_offset(uint32_t offset) {
  this->data_offset_ = offset;
}

void FunctionStarts::data_size(uint32_t size) {
  this->data_size_ = size;
}

void FunctionStarts::functions(const std::vector<uint64_t>& funcs) {
  this->functions_ = funcs;
}

const std::vector<uint64_t>& FunctionStarts::functions(void) const {
  return this->functions_;
}

std::vector<uint64_t>& FunctionStarts::functions(void) {
  return const_cast<std::vector<uint64_t>&>(static_cast<const FunctionStarts*>(this)->functions());
}

void FunctionStarts::add_function(uint64_t address) {
  this->functions_.emplace_back(address);
}

void FunctionStarts::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool FunctionStarts::operator==(const FunctionStarts& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool FunctionStarts::operator!=(const FunctionStarts& rhs) const {
  return not (*this == rhs);
}


std::ostream& FunctionStarts::print(std::ostream& os) const {
  LoadCommand::print(os);
  os << std::left;
  os << std::endl;
  os << "Function starts location:" << std::endl;
  os << std::setw(8) << "Offset" << ": 0x" << this->data_offset() << std::endl;
  os << std::setw(8) << "Size"   << ": 0x" << this->data_size()   << std::endl;
  os << "Functions (" << std::dec << this->functions().size() << "):" << std::endl;
  for (size_t i = 0; i < this->functions().size(); ++i) {
    os << "    [" << std::dec << i << "] ";
    os << "__TEXT + ";
    os << std::hex << std::setw(6) << std::setfill(' ') << this->functions()[i] << std::endl;
  }
  return os;
}


}
}
