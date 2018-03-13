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
#ifndef LIEF_ELF_SYMBOL_VERSION_REQUIREMENTS_H_
#define LIEF_ELF_SYMBOL_VERSION_REQUIREMENTS_H_

#include <string>
#include <iostream>
#include <vector>
#include <memory>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/ELF/type_traits.hpp"
#include "LIEF/ELF/Structures.hpp"
#include "LIEF/ELF/SymbolVersionAuxRequirement.hpp"

namespace LIEF {
namespace ELF {
class Parser;

//! @brief Class which modelize an entry in ``DT_VERNEED`` or ``.gnu.version_r`` table
class LIEF_API SymbolVersionRequirement : public Object {
  friend class Parser;

  public:
    SymbolVersionRequirement(void);
    SymbolVersionRequirement(const Elf64_Verneed *header);
    SymbolVersionRequirement(const Elf32_Verneed *header);
    virtual ~SymbolVersionRequirement(void);

    SymbolVersionRequirement& operator=(SymbolVersionRequirement other);
    SymbolVersionRequirement(const SymbolVersionRequirement& other);
    void swap(SymbolVersionRequirement& other);

    //! @brief Version revision
    //!
    //! This field should always have the value ``1``. It will be changed
    //! if the versioning implementation has to be changed in an incompatible way.
    uint16_t version(void) const;

    //! @brief Number of associated auxiliary entries
    uint32_t cnt(void) const;

    //! @brief Auxiliary entries
    it_symbols_version_aux_requirement       auxiliary_symbols(void);
    it_const_symbols_version_aux_requirement auxiliary_symbols(void) const;

    const std::string& name(void) const;

    void version(uint16_t version);
    void name(const std::string& name);

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const SymbolVersionRequirement& rhs) const;
    bool operator!=(const SymbolVersionRequirement& rhs) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const SymbolVersionRequirement& symr);

  private:
    symbols_version_aux_requirement_t symbol_version_aux_requirement_;
    uint16_t                          version_;
    std::string                       name_;
};

}
}
#endif

