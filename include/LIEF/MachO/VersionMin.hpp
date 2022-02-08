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
#ifndef LIEF_MACHO_VERSION_MIN_COMMAND_H_
#define LIEF_MACHO_VERSION_MIN_COMMAND_H_
#include <iostream>
#include <array>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"

#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {

namespace details {
struct version_min_command;
}

//! Class that wraps the LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_IPHONEOS, ... commands.
class LIEF_API VersionMin : public LoadCommand {

  public:
  //! Version is an array of **3** integers
  using version_t = std::array<uint32_t, 3>;

  VersionMin();
  VersionMin(const details::version_min_command& version_cmd);

  VersionMin& operator=(const VersionMin& copy);
  VersionMin(const VersionMin& copy);

  VersionMin* clone() const override;

  virtual ~VersionMin();

  //! Return the version as an array
  const version_t& version() const;
  void version(const version_t& version);

  //! Return the sdk version as an array
  const version_t& sdk() const;
  void sdk(const version_t& sdk);

  bool operator==(const VersionMin& rhs) const;
  bool operator!=(const VersionMin& rhs) const;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  static bool classof(const LoadCommand* cmd);

  private:
  version_t version_;
  version_t sdk_;
};

}
}
#endif
