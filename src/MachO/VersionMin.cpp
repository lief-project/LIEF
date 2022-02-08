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

#include "LIEF/MachO/VersionMin.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

VersionMin::VersionMin() = default;
VersionMin& VersionMin::operator=(const VersionMin&) = default;
VersionMin::VersionMin(const VersionMin&) = default;
VersionMin::~VersionMin() = default;

VersionMin::VersionMin(const details::version_min_command& version_cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(version_cmd.cmd), version_cmd.cmdsize},
  version_{{
    static_cast<uint32_t>((version_cmd.version >> 16) & 0xFFFF),
    static_cast<uint32_t>((version_cmd.version >>  8) & 0xFF),
    static_cast<uint32_t>((version_cmd.version >>  0) & 0xFF)
  }},
  sdk_{{
    static_cast<uint32_t>((version_cmd.sdk >> 16) & 0xFFFF),
    static_cast<uint32_t>((version_cmd.sdk >>  8) & 0xFF),
    static_cast<uint32_t>((version_cmd.sdk >>  0) & 0xFF)
  }}
{
}

VersionMin* VersionMin::clone() const {
  return new VersionMin(*this);
}


 const VersionMin::version_t& VersionMin::version() const {
   return version_;
 }

 void VersionMin::version(const VersionMin::version_t& version) {
   version_ = version;
 }

 const VersionMin::version_t& VersionMin::sdk() const {
   return sdk_;
 }

 void VersionMin::sdk(const VersionMin::version_t& version) {
   sdk_ = version;
 }

void VersionMin::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool VersionMin::operator==(const VersionMin& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool VersionMin::operator!=(const VersionMin& rhs) const {
  return !(*this == rhs);
}


bool VersionMin::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_VERSION_MIN_MACOSX ||
         type == LOAD_COMMAND_TYPES::LC_VERSION_MIN_IPHONEOS;
}

std::ostream& VersionMin::print(std::ostream& os) const {
  LoadCommand::print(os);
  const VersionMin::version_t& version = this->version();
  const VersionMin::version_t& sdk = this->sdk();
  os << std::setw(10) << "Version: " << std::dec
     << version[0] << "."
     << version[1] << "."
     << version[2] << std::endl;

  os << std::setw(10) << "SDK: " << std::dec
     << sdk[0] << "."
     << sdk[1] << "."
     << sdk[2] << std::endl;

  return os;
}


}
}
