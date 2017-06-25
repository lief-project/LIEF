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
#ifndef LIEF_ELF_SYMBOL_H_
#define LIEF_ELF_SYMBOL_H_

#include <string>
#include <vector>
#include <iostream>

#include "LIEF/visibility.h"

#include "LIEF/Abstract/Symbol.hpp"

#include "LIEF/ELF/Structures.hpp"
#include "LIEF/ELF/Section.hpp"
#include "LIEF/ELF/SymbolVersion.hpp"


namespace LIEF {
namespace ELF {
class Parser;
class Binary;

class DLL_PUBLIC Symbol : public LIEF::Symbol {
  friend class Parser;
  friend class Binary;

  public:
    Symbol(const Elf32_Sym* header);
    Symbol(const Elf64_Sym* header);
    Symbol(std::string name,
        SYMBOL_TYPES type = SYMBOL_TYPES::STT_NOTYPE,
        SYMBOL_BINDINGS binding = SYMBOL_BINDINGS::STB_WEAK,
        uint8_t other = 0, uint16_t shndx = 0,
        uint64_t value = 0, uint64_t size = 0);
    Symbol(void);
    virtual ~Symbol(void);

    Symbol& operator=(Symbol other);
    Symbol(const Symbol& other);
    void swap(Symbol& other);

    SYMBOL_TYPES         type(void) const;
    SYMBOL_BINDINGS      binding(void) const;
    uint8_t              information(void) const;
    uint8_t              other(void) const;
    uint16_t             section_idx(void) const;
    Section&             section(void);
    uint64_t             value(void) const;
    uint64_t             size(void) const;
    uint16_t             shndx(void) const;
    bool                 has_version(void) const;
    SymbolVersion&       symbol_version(void);
    const SymbolVersion& symbol_version(void) const;

    std::string          demangled_name(void) const;

    void type(SYMBOL_TYPES type);
    void binding(SYMBOL_BINDINGS binding);
    void other(uint8_t other);
    void value(uint64_t value);
    void size(uint64_t size);
    void information(uint8_t info);
    void shndx(uint16_t idx);

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const Symbol& rhs) const;
    bool operator!=(const Symbol& rhs) const;

    DLL_PUBLIC friend std::ostream& operator<<(std::ostream& os, const Symbol& entry);

  private:
    SYMBOL_TYPES    type_;
    SYMBOL_BINDINGS binding_;
    uint8_t         other_;
    uint16_t        shndx_;
    Section*        section_;
    uint64_t        value_;
    uint64_t        size_;
    SymbolVersion*  symbol_version_;

};
}
}
#endif /* _ELF_SYMBOL_H_ */
