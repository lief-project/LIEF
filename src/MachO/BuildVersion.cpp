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

#include "LIEF/MachO/EnumToString.hpp"
#include "LIEF/MachO/BuildVersion.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

BuildToolVersion::BuildToolVersion() = default;
BuildToolVersion::BuildToolVersion(const details::build_tool_version& tool) :
  tool_{static_cast<BuildToolVersion::TOOLS>(tool.tool)},
  version_{{
    static_cast<uint32_t>((tool.version >> 16) & 0xFFFF),
    static_cast<uint32_t>((tool.version >>  8) & 0xFF),
    static_cast<uint32_t>((tool.version >>  0) & 0xFF)
  }}
{}

BuildToolVersion::TOOLS BuildToolVersion::tool() const {
  return tool_;
}

BuildToolVersion::version_t BuildToolVersion::version() const {
  return version_;
}

BuildToolVersion::~BuildToolVersion() = default;

bool BuildToolVersion::operator==(const BuildToolVersion& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool BuildToolVersion::operator!=(const BuildToolVersion& rhs) const {
  return !(*this == rhs);
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

BuildVersion::BuildVersion() = default;
BuildVersion& BuildVersion::operator=(const BuildVersion&) = default;
BuildVersion::BuildVersion(const BuildVersion&) = default;
BuildVersion::~BuildVersion() = default;

BuildVersion::BuildVersion(const details::build_version_command& ver) :
  LoadCommand::LoadCommand{static_cast<LOAD_COMMAND_TYPES>(ver.cmd), ver.cmdsize},
  platform_{static_cast<BuildVersion::PLATFORMS>(ver.platform)},
  minos_{{
    static_cast<uint32_t>((ver.minos >> 16) & 0xFFFF),
    static_cast<uint32_t>((ver.minos >>  8) & 0xFF),
    static_cast<uint32_t>((ver.minos >>  0) & 0xFF)
  }},
  sdk_{{
    static_cast<uint32_t>((ver.sdk >> 16) & 0xFFFF),
    static_cast<uint32_t>((ver.sdk >>  8) & 0xFF),
    static_cast<uint32_t>((ver.sdk >>  0) & 0xFF)
  }}
{
}

BuildVersion* BuildVersion::clone() const {
  return new BuildVersion(*this);
}


BuildVersion::version_t BuildVersion::minos() const {
  return minos_;
}

void BuildVersion::minos(BuildVersion::version_t version) {
  minos_ = version;
}

BuildVersion::version_t BuildVersion::sdk() const {
  return sdk_;
}

void BuildVersion::sdk(BuildVersion::version_t version) {
  sdk_ = version;
}

BuildVersion::PLATFORMS BuildVersion::platform() const {
  return platform_;
}

void BuildVersion::platform(BuildVersion::PLATFORMS plat) {
  platform_ = plat;
}


BuildVersion::tools_list_t BuildVersion::tools() const {
  return tools_;
}

void BuildVersion::accept(Visitor& visitor) const {
  visitor.visit(*this);
}


bool BuildVersion::operator==(const BuildVersion& rhs) const {
  if (this == &rhs) {
    return true;
  }
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool BuildVersion::operator!=(const BuildVersion& rhs) const {
  return !(*this == rhs);
}

bool BuildVersion::classof(const LoadCommand* cmd) {
  // This must be sync with BinaryParser.tcc
  const LOAD_COMMAND_TYPES type = cmd->command();
  return type == LOAD_COMMAND_TYPES::LC_BUILD_VERSION;
}


std::ostream& BuildVersion::print(std::ostream& os) const {
  LoadCommand::print(os);

  BuildVersion::version_t minos = this->minos();
  BuildVersion::version_t sdk   = this->sdk();

  os << std::setw(10) << "Platform: " << to_string(platform()) << std::endl;

  os << std::setw(10) << "Min OS: " << std::dec
     << minos[0] << "."
     << minos[1] << "."
     << minos[2] << std::endl;

  os << std::setw(10) << "SDK: " << std::dec
     << sdk[0] << "."
     << sdk[1] << "."
     << sdk[2] << std::endl;

  for (const BuildToolVersion& tool_version : tools()) {
    os << "  " << tool_version << std::endl;
  }
  return os;
}


}
}
