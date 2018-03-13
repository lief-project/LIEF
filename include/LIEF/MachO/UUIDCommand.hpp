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
#ifndef LIEF_MACHO_UUID_COMMAND_H_
#define LIEF_MACHO_UUID_COMMAND_H_
#include <string>
#include <vector>
#include <iostream>
#include <array>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"

#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {
using uuid_t = std::array<uint8_t, 16>;

class LIEF_API UUIDCommand : public LoadCommand {
  public:
    UUIDCommand(void);
    UUIDCommand(const uuid_command *uuidCmd);

    UUIDCommand& operator=(const UUIDCommand& copy);
    UUIDCommand(const UUIDCommand& copy);

    virtual ~UUIDCommand(void);

    uuid_t uuid(void) const;
    void   uuid(const uuid_t& uuid);

    bool operator==(const UUIDCommand& rhs) const;
    bool operator!=(const UUIDCommand& rhs) const;

    virtual void accept(Visitor& visitor) const override;

    virtual std::ostream& print(std::ostream& os) const override;

  private:
    uuid_t uuid_;
};

}
}
#endif
