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
#include <iomanip>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/DyldEnvironment.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

DyldEnvironment::DyldEnvironment() = default;
DyldEnvironment& DyldEnvironment::operator=(const DyldEnvironment&) = default;
DyldEnvironment::DyldEnvironment(const DyldEnvironment&) = default;
DyldEnvironment::~DyldEnvironment() = default;

DyldEnvironment::DyldEnvironment(const details::dylinker_command& cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd.cmd), cmd.cmdsize}
{}

DyldEnvironment* DyldEnvironment::clone() const {
  return new DyldEnvironment(*this);
}

const std::string& DyldEnvironment::value() const {
  return value_;
}

void DyldEnvironment::value(const std::string& value) {
  value_ = value;
}


void DyldEnvironment::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool DyldEnvironment::operator==(const DyldEnvironment& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DyldEnvironment::operator!=(const DyldEnvironment& rhs) const {
  return !(*this == rhs);
}

bool DyldEnvironment::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_DYLD_ENVIRONMENT;
}

std::ostream& DyldEnvironment::print(std::ostream& os) const {
  LoadCommand::print(os);
  os << std::hex;
  os << std::left
     << std::setw(35) << value();
  return os;
}

}
}
