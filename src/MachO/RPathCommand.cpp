/* Copyright 2017 - 2021 J.Rieck (based on R. Thomas's work)
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

#include "LIEF/utils.hpp"
#include "LIEF/Visitor.hpp"

#include "LIEF/MachO/RPathCommand.hpp"
#include "MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

RPathCommand::RPathCommand(const details::rpath_command& rpath) :
  LoadCommand::LoadCommand{LoadCommand::TYPE(rpath.cmd), rpath.cmdsize}
{}

void RPathCommand::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::ostream& RPathCommand::print(std::ostream& os) const {
  LoadCommand::print(os);
  os << path() << '\n';
  return os;
}

RPathCommand RPathCommand::rpath(const std::string& path) {
  LoadCommand::TYPE type = LoadCommand::TYPE::RPATH;
  details::rpath_command raw_cmd;
  raw_cmd.cmd                         = static_cast<uint32_t>(type);
  raw_cmd.cmdsize                     = align(sizeof(details::rpath_command) + path.size() + 1, sizeof(uint64_t));
  
  RPathCommand rpath{raw_cmd};
  rpath.path(path);
  rpath.data(LoadCommand::raw_t(raw_cmd.cmdsize, 0));
  return rpath;
}

}
}
