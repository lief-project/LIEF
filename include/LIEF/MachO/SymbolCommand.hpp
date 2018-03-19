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
#ifndef LIEF_MACHO_SYMBOL_COMMAND_H_
#define LIEF_MACHO_SYMBOL_COMMAND_H_

#include <string>
#include <iostream>

#include "LIEF/visibility.h"

#include "LIEF/types.hpp"
#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {
class LIEF_API SymbolCommand : public LoadCommand {
  public:
    SymbolCommand(void);
    SymbolCommand(const symtab_command *command);

    SymbolCommand& operator=(const SymbolCommand& copy);
    SymbolCommand(const SymbolCommand& copy);

    virtual ~SymbolCommand(void);

    //! Offset from the start of the file to the n_list associated with the command
    uint32_t symbol_offset(void) const;

    //! Number of symbols registered
    uint32_t numberof_symbols(void) const;

    //! Offset from the start of the file to the string table
    uint32_t strings_offset(void) const;

    //! Size of the size string table
    uint32_t strings_size(void) const;

    void symbol_offset(uint32_t offset);
    void numberof_symbols(uint32_t nb);
    void strings_offset(uint32_t offset);
    void strings_size(uint32_t size);

    virtual std::ostream& print(std::ostream& os) const override;

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const SymbolCommand& rhs) const;
    bool operator!=(const SymbolCommand& rhs) const;

  private:
    uint32_t symbolOffset_;
    uint32_t numberOfSymbols_;
    uint32_t stringsOffset_;
    uint32_t stringsSize_;
};

}
}
#endif
