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

DylibCommand::version_t DylibCommand::int2version(uint32_t version) {
  return {{
    static_cast<uint16_t>(version >> 16),
    static_cast<uint16_t>((version >> 8) & 0xFF),
    static_cast<uint16_t>(version & 0xFF),
  }};
}

uint32_t DylibCommand::version2int(DylibCommand::version_t version) {
  return (version[2]) | (version[1] << 8) | (version[0] << 16);
}

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

DylibCommand::version_t DylibCommand::current_version(void) const {
  return int2version(this->currentVersion_);
}

DylibCommand::version_t DylibCommand::compatibility_version(void) const {
  return int2version(this->compatibilityVersion_);
}

void DylibCommand::name(const std::string& name) {
  this->name_ = name;
}

void DylibCommand::timestamp(uint32_t timestamp) {
  this->timestamp_ = timestamp;
}

void DylibCommand::current_version(DylibCommand::version_t currentVersion) {
  this->currentVersion_ = version2int(currentVersion);
}

void DylibCommand::compatibility_version(DylibCommand::version_t compatibilityVersion) {
  this->compatibilityVersion_ = version2int(compatibilityVersion);
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
  const DylibCommand::version_t& current_version       = this->current_version();
  const DylibCommand::version_t& compatibility_version = this->compatibility_version();
  LoadCommand::print(os);
  os << std::hex;
  os << std::left
     << std::setw(35) << this->name()
     << this->timestamp()
     << " - "

     << std::dec
     << current_version[0] << "."
     << current_version[1] << "."
     << current_version[2]
     << " - "

     << compatibility_version[0] << "."
     << compatibility_version[1] << "."
     << compatibility_version[2];
  return os;
}

std::ostream& operator<<(std::ostream& os, const DylibCommand& command) {
  return command.print(os);
}

}
}
