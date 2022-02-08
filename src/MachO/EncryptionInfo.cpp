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
#include "LIEF/MachO/EncryptionInfo.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

EncryptionInfo::EncryptionInfo() = default;
EncryptionInfo& EncryptionInfo::operator=(const EncryptionInfo&) = default;
EncryptionInfo::EncryptionInfo(const EncryptionInfo&) = default;
EncryptionInfo::~EncryptionInfo() = default;

EncryptionInfo::EncryptionInfo(const details::encryption_info_command& cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd.cmd), cmd.cmdsize},
  coff_{cmd.cryptoff},
  csize_{cmd.cryptsize},
  cid_{cmd.cryptid}
{}


uint32_t EncryptionInfo::crypt_offset() const {
  return coff_;
}

uint32_t EncryptionInfo::crypt_size() const {
  return csize_;
}

uint32_t EncryptionInfo::crypt_id() const  {
  return cid_;
}


void EncryptionInfo::crypt_offset(uint32_t offset) {
  coff_ = offset;
}

void EncryptionInfo::crypt_size(uint32_t size) {
  csize_ = size;
}

void EncryptionInfo::crypt_id(uint32_t id) {
  cid_ = id;
}

void EncryptionInfo::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool EncryptionInfo::operator==(const EncryptionInfo& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool EncryptionInfo::operator!=(const EncryptionInfo& rhs) const {
  return !(*this == rhs);
}


bool EncryptionInfo::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_ENCRYPTION_INFO ||
         type == LOAD_COMMAND_TYPES::LC_ENCRYPTION_INFO_64;
}


std::ostream& EncryptionInfo::print(std::ostream& os) const {
  LoadCommand::print(os);
  return os;
}


}
}
