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
#ifndef LIEF_MACHO_SOURCE_VERSION_COMMAND_H_
#define LIEF_MACHO_SOURCE_VERSION_COMMAND_H_
#include <iostream>
#include <array>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"

#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {

namespace details {
struct source_version_command;
}

//! Class that represents the MachO LOAD_COMMAND_TYPES::LC_SOURCE_VERSION
//! This command is used to provide the *version* of the sources used to build the binary
class LIEF_API SourceVersion : public LoadCommand {

  public:
  //! Version is an array of **5** integers
  using version_t = std::array<uint32_t, 5>;

  SourceVersion();
  SourceVersion(const details::source_version_command& version_cmd);

  SourceVersion& operator=(const SourceVersion& copy);
  SourceVersion(const SourceVersion& copy);

  SourceVersion* clone() const override;

  virtual ~SourceVersion();

  //! Return the version as an array
  const SourceVersion::version_t& version() const;
  void version(const SourceVersion::version_t& version);

  bool operator==(const SourceVersion& rhs) const;
  bool operator!=(const SourceVersion& rhs) const;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  static bool classof(const LoadCommand* cmd);

  private:
  SourceVersion::version_t version_;
};

}
}
#endif
