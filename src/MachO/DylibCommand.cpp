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
#include <iomanip>

#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/DylibCommand.hpp"

namespace LIEF {
namespace MachO {

DylibCommand::DylibCommand(void) = default;
DylibCommand& DylibCommand::operator=(const DylibCommand&) = default;
DylibCommand::DylibCommand(const DylibCommand&) = default;
DylibCommand::~DylibCommand(void) = default;

DylibCommand::DylibCommand(const dylib_command *cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd->cmd), cmd->cmdsize},
  timestamp_{cmd->dylib.timestamp},
  currentVersion_{cmd->dylib.current_version},
  compatibilityVersion_{cmd->dylib.compatibility_version}
{
}

const std::string& DylibCommand::name(void) const {
  return this->name_;
}

uint32_t DylibCommand::timestamp(void) const {
  return this->timestamp_;
}

uint32_t DylibCommand::current_version(void) const {
  return this->currentVersion_;
}

uint32_t DylibCommand::compatibility_version(void) const {
  return this->compatibilityVersion_;
}

void DylibCommand::name(const std::string& name) {
  this->name_ = name;
}

void DylibCommand::timestamp(uint32_t timestamp) {
  this->timestamp_ = timestamp;
}

void DylibCommand::current_version(uint32_t currentVersion) {
  this->currentVersion_ = currentVersion;
}

void DylibCommand::compatibility_version(uint32_t compatibilityVersion) {
  this->compatibilityVersion_ = compatibilityVersion;
}


void DylibCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool DylibCommand::operator==(const DylibCommand& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DylibCommand::operator!=(const DylibCommand& rhs) const {
  return not (*this == rhs);
}


std::ostream& DylibCommand::print(std::ostream& os) const {
  LoadCommand::print(os);
  os << std::hex;
  os << std::left
     << std::setw(35) << this->name()
     << std::setw(10) << this->timestamp()
     << std::setw(10) << this->current_version()
     << std::setw(10) << this->compatibility_version();

  return os;
}

std::ostream& operator<<(std::ostream& os, const DylibCommand& command) {
  return command.print(os);
}

}
}
