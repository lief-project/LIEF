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
#ifndef LIEF_ELF_SYMBOL_VERSION_AUX_REQUIREMENT_H_
#define LIEF_ELF_SYMBOL_VERSION_AUX_REQUIREMENT_H_

#include <string>
#include <iostream>

#include "LIEF/visibility.h"

#include "LIEF/ELF/Structures.hpp"
#include "LIEF/ELF/SymbolVersionAux.hpp"

namespace LIEF {
namespace ELF {
class LIEF_API SymbolVersionAuxRequirement : public SymbolVersionAux {
  public:
    using SymbolVersionAux::name;

    SymbolVersionAuxRequirement(const Elf64_Vernaux *header);
    SymbolVersionAuxRequirement(const Elf32_Vernaux *header);
    SymbolVersionAuxRequirement(void);

    SymbolVersionAuxRequirement& operator=(const SymbolVersionAuxRequirement&);
    SymbolVersionAuxRequirement(const SymbolVersionAuxRequirement&);

    virtual ~SymbolVersionAuxRequirement(void);


    //! @brief Hash value of the dependency name (use ELF hashing function)
    uint32_t hash(void) const;

    //! @brief Bitmask of flags
    uint16_t flags(void) const;

    //! @brief Contains version index unique for the file which is used in the
    //! version symbol table.  If the highest bit (bit 15) is set this
    //! is a hidden symbol which cannot be referenced from outside the
    //! object.
    uint16_t other(void) const;

    void hash(uint32_t hash);
    void flags(uint16_t flags);
    void other(uint16_t other);

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const SymbolVersionAuxRequirement& rhs) const;
    bool operator!=(const SymbolVersionAuxRequirement& rhs) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const SymbolVersionAuxRequirement& symAux);

  private:
    uint32_t hash_;
    uint16_t flags_;
    uint16_t other_;
};
}
}
#endif
