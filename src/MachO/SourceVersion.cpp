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

#include "LIEF/MachO/SourceVersion.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

SourceVersion::SourceVersion() = default;
SourceVersion& SourceVersion::operator=(const SourceVersion&) = default;
SourceVersion::SourceVersion(const SourceVersion&) = default;
SourceVersion::~SourceVersion() = default;

SourceVersion::SourceVersion(const details::source_version_command& ver) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(ver.cmd), ver.cmdsize},
  version_{{
    static_cast<uint32_t>((ver.version >> 40) & 0xffffff),
    static_cast<uint32_t>((ver.version >> 30) & 0x3ff),
    static_cast<uint32_t>((ver.version >> 20) & 0x3ff),
    static_cast<uint32_t>((ver.version >> 10) & 0x3ff),
    static_cast<uint32_t>((ver.version >>  0) & 0x3ff)
  }}
{}

SourceVersion* SourceVersion::clone() const {
  return new SourceVersion(*this);
}


 const SourceVersion::version_t& SourceVersion::version() const {
   return version_;
 }

 void SourceVersion::version(const SourceVersion::version_t& version) {
   version_ = version;
 }

void SourceVersion::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool SourceVersion::operator==(const SourceVersion& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool SourceVersion::operator!=(const SourceVersion& rhs) const {
  return !(*this == rhs);
}

bool SourceVersion::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_SOURCE_VERSION;
}

std::ostream& SourceVersion::print(std::ostream& os) const {
  LoadCommand::print(os);
  const SourceVersion::version_t& version = this->version();
  os << "Version: " << std::dec
     << version[0] << "."
     << version[1] << "."
     << version[2] << "."
     << version[3] << "."
     << version[4]
     << std::endl;

  return os;
}


}
}
