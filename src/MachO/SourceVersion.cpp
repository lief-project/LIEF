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

#include "LIEF/MachO/SourceVersion.hpp"

namespace LIEF {
namespace MachO {

SourceVersion::SourceVersion(void) = default;
SourceVersion& SourceVersion::operator=(const SourceVersion&) = default;
SourceVersion::SourceVersion(const SourceVersion&) = default;
SourceVersion::~SourceVersion(void) = default;

SourceVersion::SourceVersion(const source_version_command *version_cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(version_cmd->cmd), version_cmd->cmdsize},
  version_{{
    static_cast<uint32_t>((version_cmd->version >> 40) & 0xffffff),
    static_cast<uint32_t>((version_cmd->version >> 30) & 0x3ff),
    static_cast<uint32_t>((version_cmd->version >> 20) & 0x3ff),
    static_cast<uint32_t>((version_cmd->version >> 10) & 0x3ff),
    static_cast<uint32_t>((version_cmd->version >>  0) & 0x3ff)
  }}
{}


 const SourceVersion::version_t& SourceVersion::version(void) const {
   return this->version_;
 }

 void SourceVersion::version(const SourceVersion::version_t& version) {
   this->version_ = version;
 }

void SourceVersion::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool SourceVersion::operator==(const SourceVersion& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool SourceVersion::operator!=(const SourceVersion& rhs) const {
  return not (*this == rhs);
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
