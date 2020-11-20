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
#include "LIEF/MachO/Structures.hpp"
#include "LIEF/MachO/EncryptionInfo.hpp"

namespace LIEF {
namespace MachO {

EncryptionInfo::EncryptionInfo(void) = default;
EncryptionInfo& EncryptionInfo::operator=(const EncryptionInfo&) = default;
EncryptionInfo::EncryptionInfo(const EncryptionInfo&) = default;
EncryptionInfo::~EncryptionInfo(void) = default;

EncryptionInfo::EncryptionInfo(const encryption_info_command *cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd->cmd), cmd->cmdsize},
  coff_{cmd->cryptoff},
  csize_{cmd->cryptsize},
  cid_{cmd->cryptid}
{}


uint32_t EncryptionInfo::crypt_offset(void) const {
  return this->coff_;
}

uint32_t EncryptionInfo::crypt_size(void) const {
  return this->csize_;
}

uint32_t EncryptionInfo::crypt_id(void) const  {
  return this->cid_;
}


void EncryptionInfo::crypt_offset(uint32_t offset) {
  this->coff_ = offset;
}

void EncryptionInfo::crypt_size(uint32_t size) {
  this->csize_ = size;
}

void EncryptionInfo::crypt_id(uint32_t id) {
  this->cid_ = id;
}

void EncryptionInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool EncryptionInfo::operator==(const EncryptionInfo& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool EncryptionInfo::operator!=(const EncryptionInfo& rhs) const {
  return not (*this == rhs);
}


std::ostream& EncryptionInfo::print(std::ostream& os) const {
  LoadCommand::print(os);
  return os;
}


}
}
