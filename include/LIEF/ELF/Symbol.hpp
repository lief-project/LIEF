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

class LIEF_API Symbol : public LIEF::Symbol {
  friend class Parser;
  friend class Binary;

  public:
    Symbol(const Elf32_Sym* header);
    Symbol(const Elf64_Sym* header);
    Symbol(std::string name,
        ELF_SYMBOL_TYPES type = ELF_SYMBOL_TYPES::STT_NOTYPE,
        SYMBOL_BINDINGS binding = SYMBOL_BINDINGS::STB_WEAK,
        uint8_t other = 0, uint16_t shndx = 0,
        uint64_t value = 0, uint64_t size = 0);
    Symbol(void);
    virtual ~Symbol(void);

    Symbol& operator=(Symbol other);
    Symbol(const Symbol& other);
    void swap(Symbol& other);

    //! @brief A symbol's type provides a general classification for the associated entity
    ELF_SYMBOL_TYPES type(void) const;

    //! @brief A symbol's binding determines the linkage visibility and behavior
    SYMBOL_BINDINGS binding(void) const;

    //! @brief This member specifies the symbol's type and binding attributes.
    uint8_t information(void) const;

    //! @brief This member currently holds ``0`` and has no defined meaning.
    uint8_t other(void) const;

    //! @brief @link ELF::Section section@endlink index associated with the symbol
    uint16_t section_idx(void) const;

    ELF_SYMBOL_VISIBILITY visibility(void) const;

    Section& section(void);

    //! This member have slightly different interpretations:
    //!   * In relocatable files, `value` holds alignment constraints for a symbol whose section index
    //!     is SHN_COMMON
    //!   * In relocatable files, `value` holds a section offset for a defined symbol. That is, `value` is an
    //!     offset from the beginning of the section associated with this symbol.
    //!   * In executable and shared object files, `value` holds a virtual address. To make these files's
    //!     symbols more useful for the dynamic linker, the section offset (file interpretation) gives way to
    //!     a virtual address (memory interpretation) for which the section number is irrelevant.
    uint64_t value(void) const;

    //! @brief Symbol size
    //!
    //! Many symbols have associated sizes. For example, a data object's size is the number of
    //! bytes contained in the object. This member holds `0` if the symbol has no size or
    //! an unknown size.
    uint64_t size(void) const;

    //! @brief @see Symbol::section_idx
    uint16_t shndx(void) const;

    //! @brief Check if this symbols has a @link ELF::SymbolVersion symbol version @endlink
    bool has_version(void) const;

    //! @brief Return the @link ELF::SymbolVersion symbol version @endlink associated with this symbol
    SymbolVersion&       symbol_version(void);
    const SymbolVersion& symbol_version(void) const;

    //! @brief Symbol's unmangled name
    std::string demangled_name(void) const;

    void type(ELF_SYMBOL_TYPES type);
    void binding(SYMBOL_BINDINGS binding);
    void other(uint8_t other);
    void visibility(ELF_SYMBOL_VISIBILITY visibility);
    void value(uint64_t value);
    void size(uint64_t size);
    void information(uint8_t info);
    void shndx(uint16_t idx);

    inline void shndx(SYMBOL_SECTION_INDEX idx) {
      this->shndx_ = static_cast<uint16_t>(idx);
    }

    //! @brief Check if the current symbol is exported
    bool is_exported(void) const;

    //! @brief Set whether or not the symbol is exported
    void set_exported(bool flag = true);

    //! @brief Check if the current symbol is imported
    bool is_imported(void) const;

    //! @brief Set whether or not the symbol is imported
    void set_imported(bool flag = true);


    //! True if the symbol is a static one
    inline bool is_static(void) const {
      return this->binding() == SYMBOL_BINDINGS::STB_GLOBAL;
    }

    //! True if the symbol represent a function
    inline bool is_function(void) const {
      return this->type() == ELF_SYMBOL_TYPES::STT_FUNC;
    }

    //! True if the symbol represent a variable
    inline bool is_variable(void) const {
      return this->type() == ELF_SYMBOL_TYPES::STT_OBJECT;
    }

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const Symbol& rhs) const;
    bool operator!=(const Symbol& rhs) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const Symbol& entry);

  private:
    ELF_SYMBOL_TYPES type_;
    SYMBOL_BINDINGS  binding_;
    uint8_t          other_;
    uint16_t         shndx_;
    Section*         section_;
    uint64_t         value_;
    uint64_t         size_;
    SymbolVersion*   symbol_version_;

};
}
}
#endif /* _ELF_SYMBOL_H_ */
