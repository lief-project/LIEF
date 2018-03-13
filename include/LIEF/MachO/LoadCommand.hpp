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
#ifndef LIEF_MACHO_LOAD_COMMAND_H_
#define LIEF_MACHO_LOAD_COMMAND_H_

#include <string>
#include <vector>

#include "LIEF/types.hpp"
#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/MachO/Structures.hpp"


namespace LIEF {
namespace MachO {
class LIEF_API LoadCommand : public Object {
  public:
    LoadCommand(void);
    LoadCommand(const load_command* command);
    LoadCommand(LOAD_COMMAND_TYPES type, uint32_t size);

    LoadCommand& operator=(const LoadCommand& copy);
    LoadCommand(const LoadCommand& copy);

    void swap(LoadCommand& other);

    virtual ~LoadCommand(void);

    LOAD_COMMAND_TYPES          command(void) const;
    uint32_t                    size(void) const;
    const std::vector<uint8_t>& data(void) const;
    uint64_t                    command_offset(void) const;

    void data(const std::vector<uint8_t>& data);
    void command(LOAD_COMMAND_TYPES command);
    void size(uint32_t size);
    void command_offset(uint64_t offset);

    virtual std::ostream& print(std::ostream& os) const;

    bool operator==(const LoadCommand& rhs) const;
    bool operator!=(const LoadCommand& rhs) const;

    virtual void accept(Visitor& visitor) const override;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const LoadCommand& cmd);

  protected:
    std::vector<uint8_t> originalData_;
    LOAD_COMMAND_TYPES   command_;
    uint32_t             size_;
    uint64_t             commandOffset_;
};

}
}
#endif
