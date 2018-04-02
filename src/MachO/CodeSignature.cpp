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

#include "LIEF/MachO/CodeSignature.hpp"

namespace LIEF {
namespace MachO {

CodeSignature::CodeSignature(void) = default;
CodeSignature& CodeSignature::operator=(const CodeSignature&) = default;
CodeSignature::CodeSignature(const CodeSignature&) = default;
CodeSignature::~CodeSignature(void) = default;

CodeSignature::CodeSignature(const linkedit_data_command *cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd->cmd), cmd->cmdsize},
  data_offset_{cmd->dataoff},
  data_size_{cmd->datasize}
{}

uint32_t CodeSignature::data_offset(void) const {
  return this->data_offset_;
}

uint32_t CodeSignature::data_size(void) const {
  return this->data_size_;
}

void CodeSignature::data_offset(uint32_t offset) {
  this->data_offset_ = offset;
}

void CodeSignature::data_size(uint32_t size) {
  this->data_size_ = size;
}
void CodeSignature::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool CodeSignature::operator==(const CodeSignature& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool CodeSignature::operator!=(const CodeSignature& rhs) const {
  return not (*this == rhs);
}


std::ostream& CodeSignature::print(std::ostream& os) const {
  LoadCommand::print(os);
  os << std::left;
  os << std::endl;
  os << "Code Signature location:" << std::endl;
  os << std::setw(8) << "Offset" << ": 0x" << this->data_offset() << std::endl;
  os << std::setw(8) << "Size"   << ": 0x" << this->data_size()   << std::endl;
  return os;
}


}
}
