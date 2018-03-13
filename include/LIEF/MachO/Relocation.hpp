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

#include "LIEF/Abstract/Relocation.hpp"

#include "LIEF/visibility.h"
#include "LIEF/types.hpp"
#include "LIEF/Object.hpp"

#include "LIEF/MachO/Structures.hpp"

namespace LIEF {
namespace MachO {

class BinaryParser;

//! @brief Object modeling relocation
//!
//! @see:
//!   * MachO::RelocationObject
//!   * MachO::RelocationDyld
class LIEF_API Relocation : public LIEF::Relocation {

  friend class BinaryParser;

  public:
    using LIEF::Relocation::address;
    using LIEF::Relocation::size;

    Relocation(void);
    Relocation(uint64_t address, uint8_t type);

    //Relocation& operator=(const Relocation& other);
    Relocation(const Relocation& other);
    void swap(Relocation& other);

    virtual ~Relocation(void);

    virtual Relocation* clone(void) const = 0;

    //! @brief For @link MachO::FILE_TYPES::MH_OBJECT object @endlink this is an
    //! offset from the start of the @link MachO::Section section @endlink
    //! to the item containing the address requiring relocation.
    //virtual uint64_t address(void) const override;

    //! @brief Indicates whether the item containing the address to be
    //! relocated is part of a CPU instruction that uses PC-relative addressing.
    //!
    //! For addresses contained in PC-relative instructions, the CPU adds the address of
    //! the instruction to the address contained in the instruction.
    virtual bool is_pc_relative(void) const = 0;

    //! @brief Type of the relocation according to the
    //! @link Relocation::architecture architecture@endlink and/or
    //! @link Relocation::origin origin@endlink
    //!
    //! See:
    //!   * MachO::X86_RELOCATION
    //!   * MachO::X86_64_RELOCATION
    //!   * MachO::PPC_RELOCATION
    //!   * MachO::ARM_RELOCATION
    //!   * MachO::ARM64_RELOCATION
    //!   * MachO::REBASE_TYPES
    virtual uint8_t type(void) const;

    //! @brief @link Relocation::architecture architecture @endlink of the relocation
    CPU_TYPES architecture(void) const;

    //! @brief Origin of the relocation
    virtual RELOCATION_ORIGINS origin(void) const = 0;

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

    //! @brief ``true`` if the relocation has a SegmentCommand associated with
    bool has_segment(void) const;

    //! @brief SegmentCommand associated with the relocation (if any)
    SegmentCommand& segment(void);
    const SegmentCommand& segment(void) const;

    //virtual void address(uint64_t address) override;
    virtual void pc_relative(bool val) = 0;
    virtual void type(uint8_t type);

    bool operator==(const Relocation& rhs) const;
    bool operator!=(const Relocation& rhs) const;

    virtual void accept(Visitor& visitor) const override;

    virtual std::ostream& print(std::ostream& os) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const Relocation& relocation);



  protected:
    Symbol*            symbol_;
    uint8_t            type_;
    CPU_TYPES          architecture_;
    Section*           section_;
    SegmentCommand*    segment_;

};

}
}
#endif
