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
#ifndef LIEF_MACHO_RELOCATION_COMMAND_H_
#define LIEF_MACHO_RELOCATION_COMMAND_H_
#include <string>
#include <vector>
#include <iostream>
#include <array>

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"
#include "LIEF/Visitable.hpp"

#include "LIEF/MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

class BinaryParser;

class DLL_PUBLIC Relocation : public Visitable {

  friend class BinaryParser;

  public:
    Relocation(void);
    Relocation(const relocation_info *relocinfo);
    Relocation(const scattered_relocation_info *scattered_relocinfo);

    Relocation& operator=(Relocation other);
    Relocation(const Relocation& other);
    void swap(Relocation& other);

    virtual ~Relocation(void);

    //! @brief For @link MachO::FILE_TYPES::MH_OBJECT object @endlink this is an
    //! offset from the start of the @link MachO::Section section @endlink
    //! to the item containing the address requiring relocation.
    uint32_t address(void) const;

    //! @brief Indicates whether the item containing the address to be
    //! relocated is part of a CPU instruction that uses PC-relative addressing.
    //!
    //! For addresses contained in PC-relative instructions, the CPU adds the address of
    //! the instruction to the address contained in the instruction.
    bool is_pc_relative(void) const;

    //! @brief Indicates the length of the item containing the address to be relocated.
    //! The following table lists values and the corresponding address length.
    //!
    //! * 0: 1 byte
    //! * 1: 2 bytes
    //! * 2: 4 bytes
    //! * 3: 4 bytes
    uint8_t size(void) const;

    //! @brief Type of the relocation according to the
    //! @link Relocation::architecture architecture @endlink
    //!
    //! See:
    //!   * MachO::X86_RELOCATION
    //!   * MachO::X86_64_RELOCATION
    //!   * MachO::PPC_RELOCATION
    //!   * MachO::ARM_RELOCATION
    //!   * MachO::ARM64_RELOCATION
    uint8_t type(void) const;

    //! @brief ``true`` if the relocation is a scattered one
    bool is_scattered(void) const;

    //! @brief For **scattered** relocations,
    //! The address of the relocatable expression for the item in the file that needs
    //! to be updated if the address is changed.
    //!
    //! For relocatable expressions with the difference of two section addresses,
    //! the address from which to subtract (in mathematical terms, the minuend)
    //! is contained in the first relocation entry and the address to subtract (the subtrahend)
    //! is contained in the second relocation entry.
    int32_t value(void) const;

    //! @brief @link Relocation::architecture architecture @endlink of the relocation
    CPU_TYPES architecture(void) const;

    //! @brief ``true`` if the relocation has a symbol associated with
    bool has_symbol(void) const;

    //! @brief Symbol associated with the relocation (if any)
    Symbol& symbol(void);
    const Symbol& symbol(void) const;

    //! @brief ``true`` if the relocation has a section associated with
    bool has_section(void) const;

    //! @brief Section associated with the relocation (if any)
    Section& section(void);
    const Section& section(void) const;

    void address(uint32_t address);
    void pc_relative(bool val);
    void size(uint8_t size);
    void type(uint8_t type);
    void value(int32_t value);

    bool operator==(const Relocation& rhs) const;
    bool operator!=(const Relocation& rhs) const;

    virtual void accept(Visitor& visitor) const override;

    DLL_PUBLIC friend std::ostream& operator<<(std::ostream& os, const Relocation& relocation);

  private:
    uint32_t  address_;
    Symbol*   symbol_;
    bool      is_pcrel_;
    uint8_t   size_;
    uint8_t   type_;
    CPU_TYPES architecture_;
    bool      is_scattered_;
    int32_t   value_;
    Section*  section_;

};

}
}
#endif
