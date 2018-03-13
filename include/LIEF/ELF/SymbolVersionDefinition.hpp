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
#ifndef LIEF_ELF_SYMBOL_VERSION_DEFINITION_H_
#define LIEF_ELF_SYMBOL_VERSION_DEFINITION_H_

#include <string>
#include <iostream>
#include <vector>
#include <memory>
#include <functional>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/ELF/type_traits.hpp"
#include "LIEF/ELF/Structures.hpp"
#include "LIEF/ELF/SymbolVersionAux.hpp"

namespace LIEF {
namespace ELF {

class Parser;

//! @brief Class which modelization of an entry defined in ``DT_VERDEF``
//! (or ``.gnu.version_d``)
class LIEF_API SymbolVersionDefinition : public Object {
  friend class Parser;
  public:
    SymbolVersionDefinition(void);
    SymbolVersionDefinition(const Elf64_Verdef *header);
    SymbolVersionDefinition(const Elf32_Verdef *header);
    virtual ~SymbolVersionDefinition(void);

    SymbolVersionDefinition& operator=(SymbolVersionDefinition other);
    SymbolVersionDefinition(const SymbolVersionDefinition& other);
    void swap(SymbolVersionDefinition& other);


    //! @brief Version revision
    //!
    //! This field should always have the value ``1``. It will be changed
    //! if the versioning implementation has to be changed in an incompatible way.
    uint16_t version(void) const;

    //! @brief Version information
    uint16_t flags(void) const;

    //! @brief Version index
    //!
    //! Numeric value used as an index in the LIEF::ELF::SymbolVersion table
    uint16_t ndx(void) const;

    //! @brief Hash value of the symbol's name (using ELF hash function)
    uint32_t hash(void) const;

    //! @brief SymbolVersionAux entries
    it_symbols_version_aux       symbols_aux(void);
    it_const_symbols_version_aux symbols_aux(void) const;

    void version(uint16_t version);
    void flags(uint16_t flags);
    void hash(uint32_t hash);

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const SymbolVersionDefinition& rhs) const;
    bool operator!=(const SymbolVersionDefinition& rhs) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const SymbolVersionDefinition& sym);

  private:
    uint16_t version_;
    uint16_t flags_;
    uint16_t ndx_;
    uint32_t hash_;
    symbols_version_aux_t symbol_version_aux_;
};
}
}
#endif

