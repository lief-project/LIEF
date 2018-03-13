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
#ifndef LIEF_PE_SYMBOLS_H_
#define LIEF_PE_SYMBOLS_H_

#include <string>
#include <memory>
#include <vector>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/Abstract/Symbol.hpp"

#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/AuxiliarySymbol.hpp"
#include "LIEF/PE/Section.hpp"

namespace LIEF {
namespace PE {

class Parser;
class Builder;

class LIEF_API Symbol : public LIEF::Symbol {

  friend class Parser;
  friend class Builder;

  public:
    Symbol(const pe_symbol* header);

    Symbol(void);
    virtual ~Symbol(void);

    Symbol& operator=(Symbol other);
    Symbol(const Symbol& copy);
    void swap(Symbol& other);

    uint32_t             value(void) const;
    int16_t              section_number(void) const;
    uint16_t             type(void) const;
    SYMBOL_BASE_TYPES    base_type(void) const;
    SYMBOL_COMPLEX_TYPES complex_type(void) const;
    SYMBOL_STORAGE_CLASS storage_class(void) const;
    uint8_t              numberof_aux_symbols(void) const;
    std::wstring         wname(void) const;
    Section&             section(void);
    const Section&       section(void) const;

    //! @brief ``True`` if symbols are located in a section
    bool                 has_section(void) const;

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const Symbol& rhs) const;
    bool operator!=(const Symbol& rhs) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const Symbol& entry);

  private:
    uint32_t             value_;
    int16_t              section_number_;
    uint16_t             type_;
    SYMBOL_STORAGE_CLASS storage_class_;
    uint8_t              numberof_aux_symbols_;
    Section*             section_;

};


} // namespace PE
} // namespace LIEF
#endif /* SYMBOLS_H_ */
