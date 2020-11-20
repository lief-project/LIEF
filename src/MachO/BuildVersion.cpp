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

#include "LIEF/MachO/EnumToString.hpp"
#include "LIEF/MachO/Structures.hpp"
#include "LIEF/MachO/BuildVersion.hpp"

namespace LIEF {
namespace MachO {


BuildToolVersion::BuildToolVersion(void) = default;
BuildToolVersion::BuildToolVersion(const build_tool_version& tool) :
  tool_{static_cast<BuildToolVersion::TOOLS>(tool.tool)},
  version_{{
    static_cast<uint32_t>((tool.version >> 16) & 0xFFFF),
    static_cast<uint32_t>((tool.version >>  8) & 0xFF),
    static_cast<uint32_t>((tool.version >>  0) & 0xFF)
  }}
{}

BuildToolVersion::TOOLS BuildToolVersion::tool(void) const {
  return this->tool_;
}

BuildToolVersion::version_t BuildToolVersion::version(void) const {
  return this->version_;
}

BuildToolVersion::~BuildToolVersion(void) = default;

bool BuildToolVersion::operator==(const BuildToolVersion& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool BuildToolVersion::operator!=(const BuildToolVersion& rhs) const {
  return not (*this == rhs);
}

void BuildToolVersion::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& operator<<(std::ostream& os, const BuildToolVersion& tool) {
  BuildToolVersion::version_t version = tool.version();

  os << to_string(tool.tool()) << " - ";
  os << std::dec
     << version[0] << "."
     << version[1] << "."
     << version[2] << std::endl;
  return os;
}


// Build Version
// =============

BuildVersion::BuildVersion(void) = default;
BuildVersion& BuildVersion::operator=(const BuildVersion&) = default;
BuildVersion::BuildVersion(const BuildVersion&) = default;
BuildVersion::~BuildVersion(void) = default;

BuildVersion::BuildVersion(const build_version_command *version_cmd) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(version_cmd->cmd), version_cmd->cmdsize},
  platform_{static_cast<BuildVersion::PLATFORMS>(version_cmd->platform)},
  minos_{{
    static_cast<uint32_t>((version_cmd->minos >> 16) & 0xFFFF),
    static_cast<uint32_t>((version_cmd->minos >>  8) & 0xFF),
    static_cast<uint32_t>((version_cmd->minos >>  0) & 0xFF)
  }},
  sdk_{{
    static_cast<uint32_t>((version_cmd->sdk >> 16) & 0xFFFF),
    static_cast<uint32_t>((version_cmd->sdk >>  8) & 0xFF),
    static_cast<uint32_t>((version_cmd->sdk >>  0) & 0xFF)
  }}
{
}

BuildVersion* BuildVersion::clone(void) const {
  return new BuildVersion(*this);
}


BuildVersion::version_t BuildVersion::minos(void) const {
  return this->minos_;
}

void BuildVersion::minos(BuildVersion::version_t version) {
  this->minos_ = version;
}

BuildVersion::version_t BuildVersion::sdk(void) const {
  return this->sdk_;
}

void BuildVersion::sdk(BuildVersion::version_t version) {
  this->sdk_ = version;
}

BuildVersion::PLATFORMS BuildVersion::platform(void) const {
  return this->platform_;
}

void BuildVersion::platform(BuildVersion::PLATFORMS plat) {
  this->platform_ = plat;
}


BuildVersion::tools_list_t BuildVersion::tools(void) const {
  return this->tools_;
}

void BuildVersion::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool BuildVersion::operator==(const BuildVersion& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool BuildVersion::operator!=(const BuildVersion& rhs) const {
  return not (*this == rhs);
}


std::ostream& BuildVersion::print(std::ostream& os) const {
  LoadCommand::print(os);

  BuildVersion::version_t minos = this->minos();
  BuildVersion::version_t sdk   = this->sdk();

  os << std::setw(10) << "Platform: " << to_string(this->platform()) << std::endl;

  os << std::setw(10) << "Min OS: " << std::dec
     << minos[0] << "."
     << minos[1] << "."
     << minos[2] << std::endl;

  os << std::setw(10) << "SDK: " << std::dec
     << sdk[0] << "."
     << sdk[1] << "."
     << sdk[2] << std::endl;

  for (const BuildToolVersion& tool_version : this->tools()) {
    os << "  " << tool_version << std::endl;
  }
  return os;
}


}
}
