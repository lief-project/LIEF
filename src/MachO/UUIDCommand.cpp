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

#include "LIEF/MachO/UUIDCommand.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

UUIDCommand::UUIDCommand() = default;
UUIDCommand& UUIDCommand::operator=(const UUIDCommand&) = default;
UUIDCommand::UUIDCommand(const UUIDCommand&) = default;
UUIDCommand::~UUIDCommand() = default;

UUIDCommand::UUIDCommand(const details::uuid_command& uuid) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(uuid.cmd), uuid.cmdsize}
{
  std::copy(std::begin(uuid.uuid), std::end(uuid.uuid), std::begin(uuid_));
}

UUIDCommand* UUIDCommand::clone() const {
  return new UUIDCommand(*this);
}

uuid_t UUIDCommand::uuid() const {
  return uuid_;
}

void UUIDCommand::uuid(const uuid_t& uuid) {
  uuid_ = uuid;
}


void UUIDCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool UUIDCommand::operator==(const UUIDCommand& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool UUIDCommand::operator!=(const UUIDCommand& rhs) const {
  return !(*this == rhs);
}

bool UUIDCommand::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_UUID;
}


std::ostream& UUIDCommand::print(std::ostream& os) const {
  LoadCommand::print(os);
  for (uint32_t x : uuid()) {
    os << std::setw(2) << std::setfill('0') << std::hex << static_cast<uint32_t>(x) << " ";
  }
  os << std::setfill(' ');
  return os;
}


}
}
