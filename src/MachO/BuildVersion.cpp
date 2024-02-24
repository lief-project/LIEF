/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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

#include "LIEF/MachO/EnumToString.hpp"
#include "LIEF/MachO/BuildVersion.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

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

BuildVersion::BuildVersion(const PLATFORMS platform,
                           const version_t &minos,
                           const version_t &sdk,
                           const tools_list_t &tools) :
  LoadCommand::LoadCommand{LOAD_COMMAND_TYPES::LC_BUILD_VERSION,
                           static_cast<uint32_t>(sizeof(details::build_version_command) +
                           sizeof(details::build_tool_version) * tools.size())},
  platform_{platform}, minos_{minos}, sdk_{sdk}, tools_{tools}
{
  original_data_.resize(size());
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
