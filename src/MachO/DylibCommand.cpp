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
#include "LIEF/utils.hpp"
#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/Structures.hpp"
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
  current_version_{cmd->dylib.current_version},
  compatibility_version_{cmd->dylib.compatibility_version}
{}


DylibCommand* DylibCommand::clone(void) const {
  return new DylibCommand(*this);
}

const std::string& DylibCommand::name(void) const {
  return this->name_;
}

uint32_t DylibCommand::timestamp(void) const {
  return this->timestamp_;
}

DylibCommand::version_t DylibCommand::current_version(void) const {
  return int2version(this->current_version_);
}

DylibCommand::version_t DylibCommand::compatibility_version(void) const {
  return int2version(this->compatibility_version_);
}

void DylibCommand::name(const std::string& name) {
  this->name_ = name;
}

void DylibCommand::timestamp(uint32_t timestamp) {
  this->timestamp_ = timestamp;
}

void DylibCommand::current_version(DylibCommand::version_t currentVersion) {
  this->current_version_ = version2int(currentVersion);
}

void DylibCommand::compatibility_version(DylibCommand::version_t compatibilityVersion) {
  this->compatibility_version_ = version2int(compatibilityVersion);
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

// Static functions
// ================

DylibCommand DylibCommand::create(LOAD_COMMAND_TYPES type,
    const std::string& name,
    uint32_t timestamp,
    uint32_t current_version,
    uint32_t compat_version) {

  dylib_command raw_cmd;
  raw_cmd.cmd                         = static_cast<uint32_t>(type);
  raw_cmd.cmdsize                     = align(sizeof(dylib_command) + name.size() + 1, sizeof(uint64_t));
  raw_cmd.dylib.timestamp             = timestamp;
  raw_cmd.dylib.current_version       = current_version;
  raw_cmd.dylib.compatibility_version = compat_version;

  DylibCommand dylib{&raw_cmd};
  dylib.name(name);
  dylib.data(LoadCommand::raw_t(raw_cmd.cmdsize, 0));

  return dylib;
}

DylibCommand DylibCommand::load_dylib(const std::string& name,
      uint32_t timestamp,
      uint32_t current_version,
      uint32_t compat_version)
{

  return DylibCommand::create(
      LOAD_COMMAND_TYPES::LC_LOAD_DYLIB, name,
      timestamp, current_version, compat_version);
}

DylibCommand DylibCommand::weak_dylib(const std::string& name,
      uint32_t timestamp,
      uint32_t current_version,
      uint32_t compat_version)
{

  return DylibCommand::create(
      LOAD_COMMAND_TYPES::LC_LOAD_WEAK_DYLIB, name,
      timestamp, current_version, compat_version);
}

DylibCommand DylibCommand::id_dylib(const std::string& name,
      uint32_t timestamp,
      uint32_t current_version,
      uint32_t compat_version)
{

  return DylibCommand::create(
      LOAD_COMMAND_TYPES::LC_ID_DYLIB, name,
      timestamp, current_version, compat_version);
}

DylibCommand DylibCommand::reexport_dylib(const std::string& name,
      uint32_t timestamp,
      uint32_t current_version,
      uint32_t compat_version)
{

  return DylibCommand::create(
      LOAD_COMMAND_TYPES::LC_REEXPORT_DYLIB, name,
      timestamp, current_version, compat_version);
}

DylibCommand DylibCommand::load_upward_dylib(const std::string& name,
      uint32_t timestamp,
      uint32_t current_version,
      uint32_t compat_version)
{

  return DylibCommand::create(
      LOAD_COMMAND_TYPES::LC_LOAD_UPWARD_DYLIB, name,
      timestamp, current_version, compat_version);
}


DylibCommand DylibCommand::lazy_load_dylib(const std::string& name,
      uint32_t timestamp,
      uint32_t current_version,
      uint32_t compat_version)
{

  return DylibCommand::create(
      LOAD_COMMAND_TYPES::LC_LAZY_LOAD_DYLIB, name,
      timestamp, current_version, compat_version);
}


}
}
