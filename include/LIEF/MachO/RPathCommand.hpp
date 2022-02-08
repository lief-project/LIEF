/* Copyright 2017 - 2021 J. Rieck (based on R. Thomas's work)
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
#ifndef LIEF_MACHO_RPATH_COMMAND_H_
#define LIEF_MACHO_RPATH_COMMAND_H_
#include <string>
#include <iostream>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"

#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {

namespace details {
struct rpath_command;
}

//! Class that represents the LC_RPATH command.
//!
//! This command is used to add path for searching libraries
//! associated with the ``@rpath`` prefix.
class LIEF_API RPathCommand : public LoadCommand {
  public:
  RPathCommand();
  RPathCommand(const details::rpath_command& rpathCmd);

  RPathCommand& operator=(const RPathCommand& copy);
  RPathCommand(const RPathCommand& copy);

  RPathCommand* clone() const override;

  virtual ~RPathCommand();

  //! The rpath value as a string
  const std::string& path() const;
  void path(const std::string& path);

  bool operator==(const RPathCommand& rhs) const;
  bool operator!=(const RPathCommand& rhs) const;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  static bool classof(const LoadCommand* cmd);

  private:
  std::string path_;
};

}
}
#endif
