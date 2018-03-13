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

#include "LIEF/MachO/UUIDCommand.hpp"

namespace LIEF {
namespace MachO {

UUIDCommand::UUIDCommand(void) = default;
UUIDCommand& UUIDCommand::operator=(const UUIDCommand&) = default;
UUIDCommand::UUIDCommand(const UUIDCommand&) = default;
UUIDCommand::~UUIDCommand(void) = default;

UUIDCommand::UUIDCommand(const uuid_command *uuidCmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(uuidCmd->cmd), uuidCmd->cmdsize}
{
  std::copy(std::begin(uuidCmd->uuid), std::end(uuidCmd->uuid), std::begin(this->uuid_));
}

uuid_t UUIDCommand::uuid(void) const {
  return this->uuid_;
}

void UUIDCommand::uuid(const uuid_t& uuid) {
  this->uuid_ = uuid;
}


void UUIDCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool UUIDCommand::operator==(const UUIDCommand& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool UUIDCommand::operator!=(const UUIDCommand& rhs) const {
  return not (*this == rhs);
}


std::ostream& UUIDCommand::print(std::ostream& os) const {
  LoadCommand::print(os);
  for (uint32_t x : this->uuid()) {
    os << std::setw(2) << std::setfill('0') << std::hex << static_cast<uint32_t>(x) << " ";
  }
  os << std::setfill(' ');
  return os;
}


}
}
