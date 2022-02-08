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
#ifndef LIEF_MACHO_DYLIB_COMMAND_H_
#define LIEF_MACHO_DYLIB_COMMAND_H_
#include <array>
#include <string>
#include <iostream>

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {

namespace details {
struct dylib_command;
}

//! Class which represents a library dependency
class LIEF_API DylibCommand : public LoadCommand {
  public:
  using version_t = std::array<uint16_t, 3>;

  public:
  //! Helper to convert an integer into a version array
  static version_t int2version(uint32_t version);

  //! Helper to convert a version array into an integer
  static uint32_t version2int(version_t version);

  //! Factory function to generate a LC_LOAD_WEAK_DYLIB library
  static DylibCommand weak_dylib(const std::string& name,
      uint32_t timestamp = 0,
      uint32_t current_version = 0,
      uint32_t compat_version = 0);

  //! Factory function to generate a LC_ID_DYLIB library
  static DylibCommand id_dylib(const std::string& name,
      uint32_t timestamp = 0,
      uint32_t current_version = 0,
      uint32_t compat_version = 0);

  //! Factory function to generate a LC_LOAD_DYLIB library
  static DylibCommand load_dylib(const std::string& name,
      uint32_t timestamp = 2,
      uint32_t current_version = 0,
      uint32_t compat_version = 0);

  //! Factory function to generate a LC_REEXPORT_DYLIB library
  static DylibCommand reexport_dylib(const std::string& name,
      uint32_t timestamp = 0,
      uint32_t current_version = 0,
      uint32_t compat_version = 0);

  //! Factory function to generate a LC_LOAD_UPWARD_DYLIB library
  static DylibCommand load_upward_dylib(const std::string& name,
      uint32_t timestamp = 0,
      uint32_t current_version = 0,
      uint32_t compat_version = 0);

  //! Factory function to generate a LC_LAZY_LOAD_DYLIB library
  static DylibCommand lazy_load_dylib(const std::string& name,
      uint32_t timestamp = 0,
      uint32_t current_version = 0,
      uint32_t compat_version = 0);

  public:
  DylibCommand();
  DylibCommand(const details::dylib_command& cmd);

  DylibCommand& operator=(const DylibCommand& copy);
  DylibCommand(const DylibCommand& copy);

  virtual ~DylibCommand();

  DylibCommand* clone() const override;

  //! Library name
  const std::string& name() const;

  //! Date and Time when the shared library was built
  uint32_t timestamp() const;

  //! Current version of the shared library
  version_t current_version() const;

  //! Compatibility version of the shared library
  version_t compatibility_version() const;

  void name(const std::string& name);
  void timestamp(uint32_t timestamp);
  void current_version(version_t currentVersion);
  void compatibility_version(version_t compatibilityVersion);

  std::ostream& print(std::ostream& os) const override;

  bool operator==(const DylibCommand& rhs) const;
  bool operator!=(const DylibCommand& rhs) const;

  void accept(Visitor& visitor) const override;

  static bool classof(const LoadCommand* cmd);

  private:
  static DylibCommand create(LOAD_COMMAND_TYPES type,
                             const std::string& name,
                             uint32_t timestamp,
                             uint32_t current_version,
                             uint32_t compat_version);
  std::string name_;
  uint32_t timestamp_;
  uint32_t current_version_;
  uint32_t compatibility_version_;
};


}
}
#endif
