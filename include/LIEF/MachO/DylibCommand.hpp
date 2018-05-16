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
#ifndef LIEF_MACHO_DYLIB_COMMAND_H_
#define LIEF_MACHO_DYLIB_COMMAND_H_

#include <iostream>

#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

#include "LIEF/MachO/LoadCommand.hpp"


namespace LIEF {
namespace MachO {
class LIEF_API DylibCommand : public LoadCommand {

  public:
  using version_t = std::array<uint16_t, 3>;

  public:
  static version_t int2version(uint32_t version);
  static uint32_t version2int(version_t version);

  public:
    DylibCommand(void);
    DylibCommand(const dylib_command *cmd);

    DylibCommand& operator=(const DylibCommand& copy);
    DylibCommand(const DylibCommand& copy);

    virtual ~DylibCommand(void);

    const std::string& name(void) const;
    uint32_t timestamp(void) const;
    version_t current_version(void) const;
    version_t compatibility_version(void) const;

    void name(const std::string& name);
    void timestamp(uint32_t timestamp);
    void current_version(version_t currentVersion);
    void compatibility_version(version_t compatibilityVersion);

    virtual std::ostream& print(std::ostream& os) const override;

    bool operator==(const DylibCommand& rhs) const;
    bool operator!=(const DylibCommand& rhs) const;

    virtual void accept(Visitor& visitor) const override;


  private:
    std::string name_;
    uint32_t timestamp_;
    uint32_t currentVersion_;
    uint32_t compatibilityVersion_;
};


}
}
#endif
