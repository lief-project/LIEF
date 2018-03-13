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
#ifndef LIEF_MACHO_DYNAMIC_SYMBOL_COMMAND_H_
#define LIEF_MACHO_DYNAMIC_SYMBOL_COMMAND_H_
#include <string>
#include <vector>
#include <iostream>
#include <array>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"

#include "LIEF/MachO/LoadCommand.hpp"

namespace LIEF {
namespace MachO {
class LIEF_API DynamicSymbolCommand : public LoadCommand {
  public:
    DynamicSymbolCommand(void);
    DynamicSymbolCommand(const dysymtab_command *cmd);

    DynamicSymbolCommand& operator=(const DynamicSymbolCommand& copy);
    DynamicSymbolCommand(const DynamicSymbolCommand& copy);

    virtual ~DynamicSymbolCommand(void);

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const DynamicSymbolCommand& rhs) const;
    bool operator!=(const DynamicSymbolCommand& rhs) const;

    virtual std::ostream& print(std::ostream& os) const override;


  private:
    //! @brief Integer indicating the index of the first symbol in the group of local symbols.
    uint32_t idxLocalSymbol_;

    //! @brief Integer indicating the total number of symbols in the group of local symbols.
    uint32_t nbLocalSymbol_;

    //! @brief Integer indicating the index of the first symbol in the group of
    //! defined external symbols.
    uint32_t idxExternalDefineSymbol_;

    //! @brief Integer indicating the total number of symbols in the group of
    //! defined external symbols.
    uint32_t nbExternalDefineSymbol_;

    //! @brief Integer indicating the index of the first symbol in the group of
    //! undefined external symbols.
    uint32_t idxUndefineSymbol_;

    //! @brief Integer indicating the total number of symbols in the group of
    //! undefined external symbols.
    uint32_t nbUndefineSymbol_;

    //! @brief Integer indicating the byte offset from the start of
    //! the file to the table of contents data.
    uint32_t tocOffset_;

    //! @brief Integer indicating the number of entries in the table of contents.
    uint32_t nbToc_;

    //! @brief Integer indicating the byte offset from the start of
    //! the file to the module table data.
    uint32_t moduleTableOffset_;

    //! @brief Integer indicating the number of entries in the module table.
    uint32_t nbModuleTable_;

    //! @brief Integer indicating the byte offset from the start of
    //! the file to the external reference table data.
    uint32_t externalReferenceSymbolOffset_;

    //! @brief Integer indicating the number of entries in the external reference table.
    uint32_t nbExternalReferenceSymbols_;

    //! @brief Integer indicating the byte offset from the start of
    //! the file to the indirect symbol table data.
    uint32_t indirectSymOffset_;

    //! @brief Integer indicating the number of entries in the indirect symbol table.
    uint32_t nbIndirectSymbols_;

    //! @brief Integer indicating the byte offset from the start of
    //! the file to the external relocation table data.
    uint32_t externalRelocationOffset_;

    //! @brief Integer indicating the number of entries in the external relocation table.
    uint32_t nbExternalRelocation_;

    //! @brief Integer indicating the byte offset from the start of
    //! the file to the local relocation table data.
    uint32_t localRelocationOffset_;

    //! @brief An integer indicating the number of entries in the local relocation table.
    uint32_t nbLocRelocation_;
};

}
}
#endif
