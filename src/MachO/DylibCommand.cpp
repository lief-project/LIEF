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
#include "LIEF/utils.hpp"
#include "LIEF/MachO/hash.hpp"

#include "LIEF/MachO/DylibCommand.hpp"
#include "MachO/Structures.hpp"

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

DylibCommand::DylibCommand() = default;
DylibCommand& DylibCommand::operator=(const DylibCommand&) = default;
DylibCommand::DylibCommand(const DylibCommand&) = default;
DylibCommand::~DylibCommand() = default;

DylibCommand::DylibCommand(const details::dylib_command& cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(cmd.cmd), cmd.cmdsize},
  timestamp_{cmd.dylib.timestamp},
  current_version_{cmd.dylib.current_version},
  compatibility_version_{cmd.dylib.compatibility_version}
{}


DylibCommand* DylibCommand::clone() const {
  return new DylibCommand(*this);
}

const std::string& DylibCommand::name() const {
  return name_;
}

uint32_t DylibCommand::timestamp() const {
  return timestamp_;
}

DylibCommand::version_t DylibCommand::current_version() const {
  return int2version(current_version_);
}

DylibCommand::version_t DylibCommand::compatibility_version() const {
  return int2version(compatibility_version_);
}

void DylibCommand::name(const std::string& name) {
  name_ = name;
}

void DylibCommand::timestamp(uint32_t timestamp) {
  timestamp_ = timestamp;
}

void DylibCommand::current_version(DylibCommand::version_t currentVersion) {
  current_version_ = version2int(currentVersion);
}

void DylibCommand::compatibility_version(DylibCommand::version_t compatibilityVersion) {
  compatibility_version_ = version2int(compatibilityVersion);
}


void DylibCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool DylibCommand::operator==(const DylibCommand& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool DylibCommand::operator!=(const DylibCommand& rhs) const {
  return !(*this == rhs);
}


std::ostream& DylibCommand::print(std::ostream& os) const {
  const DylibCommand::version_t& current_version       = this->current_version();
  const DylibCommand::version_t& compatibility_version = this->compatibility_version();
  LoadCommand::print(os);
  os << std::hex;
  os << std::left
     << std::setw(35) << name()
     << timestamp()
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

bool DylibCommand::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_LOAD_WEAK_DYLIB ||
         type == LOAD_COMMAND_TYPES::LC_ID_DYLIB ||
         type == LOAD_COMMAND_TYPES::LC_LOAD_DYLIB ||
         type == LOAD_COMMAND_TYPES::LC_REEXPORT_DYLIB ||
         type == LOAD_COMMAND_TYPES::LC_LAZY_LOAD_DYLIB;
}

DylibCommand DylibCommand::create(LOAD_COMMAND_TYPES type,
    const std::string& name,
    uint32_t timestamp,
    uint32_t current_version,
    uint32_t compat_version) {

  details::dylib_command raw_cmd;
  raw_cmd.cmd                         = static_cast<uint32_t>(type);
  raw_cmd.cmdsize                     = align(sizeof(details::dylib_command) + name.size() + 1, sizeof(uint64_t));
  raw_cmd.dylib.timestamp             = timestamp;
  raw_cmd.dylib.current_version       = current_version;
  raw_cmd.dylib.compatibility_version = compat_version;

  DylibCommand dylib{raw_cmd};
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
