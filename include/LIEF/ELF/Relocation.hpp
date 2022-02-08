/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#ifndef LIEF_ELF_RELOCATION_H_
#define LIEF_ELF_RELOCATION_H_

#include <string>
#include <map>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/Abstract/Relocation.hpp"

#include "LIEF/ELF/enums.hpp"

namespace LIEF {
namespace ELF {

class Parser;
class Binary;
class Builder;
class Symbol;
class Section;

namespace details {
struct Elf32_Rel;
struct Elf32_Rela;

struct Elf64_Rel;
struct Elf64_Rela;
}

//! Class that represents an ELF relocation.
class LIEF_API Relocation : public LIEF::Relocation {

  friend class Parser;
  friend class Binary;
  friend class Builder;

  public:
  Relocation(const details::Elf32_Rel&  header);
  Relocation(const details::Elf32_Rela& header);
  Relocation(const details::Elf64_Rel&  header);
  Relocation(const details::Elf64_Rela& header);
  Relocation(uint64_t address, uint32_t type = 0, int64_t addend = 0, bool isRela = false);

  template<class T, typename = typename std::enable_if<std::is_enum<T>::value>::type>
  Relocation(uint64_t address, T type, int64_t addend = 0, bool isRela = false) :
    Relocation{address, static_cast<uint32_t>(type), addend, isRela}
  {}

  Relocation();
  Relocation(ARCH arch);
  ~Relocation() override;

  Relocation& operator=(Relocation other);
  Relocation(const Relocation& other);
  void swap(Relocation& other);

  //! Additional value that can be involved in the relocation processing
  int64_t  addend() const;

  //! Type of the relocation
  //! This type depends on the underlying architecture which can be accessed with architecture().
  //!
  //! Depending on the architecture, it can return:
  //!
  //! * RELOC_x86_64
  //! * RELOC_i386
  //! * RELOC_POWERPC32
  //! * RELOC_POWERPC64
  //! * RELOC_AARCH64
  //! * RELOC_ARM
  //! * RELOC_MIPS
  //! * RELOC_HEXAGON
  //! * RELOC_SYSTEMZ
  //! * RELOC_SPARC
  uint32_t type() const;

  //! Check if the relocation uses the explicit addend() field (this is usually the case for 64 bits binaries)
  bool is_rela() const;

  //! Check if the relocation uses the implicit added (i.e. not present in the ELF structure)
  bool is_rel() const;

  //! Relocation info which contains for instance the symbol index
  uint32_t info() const;

  ARCH architecture() const;
  RELOCATION_PURPOSES purpose() const;

  //! Return the size (in **bits**) of the value associated with this relocation
  //!
  //! Return -1 if it fails
  size_t size() const override;

  //! True if the current relocation is associated with a symbol
  bool has_symbol() const;

  //! Symbol associated with the relocation
  //! If no symbol is tied to this relocation, it returns a nullptr
  Symbol*       symbol();
  const Symbol* symbol() const;

  //! True if the relocation has an associated section
  bool has_section() const;

  //! Section associated with this relocation.
  //! If no section is tied to this relocation, it returns a nullptr
  Section*       section();
  const Section* section() const;

  void addend(int64_t addend);
  void type(uint32_t type);
  void purpose(RELOCATION_PURPOSES purpose);
  void info(uint32_t v);
  void symbol(Symbol* symbol);
  void section(Section* section);

  void accept(Visitor& visitor) const override;

  bool operator==(const Relocation& rhs) const;
  bool operator!=(const Relocation& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Relocation& entry);

  private:
  uint32_t            type_ = 0;
  int64_t             addend_ = 0;
  bool                isRela_ = false;
  Symbol*             symbol_ = nullptr;
  ARCH                architecture_ = ARCH::EM_NONE;
  RELOCATION_PURPOSES purpose_ = RELOCATION_PURPOSES::RELOC_PURPOSE_NONE;
  Section*            section_{nullptr};
  uint32_t            info_ = 0;
};



}
}
#endif /* _ELF_RELOCATION_H_ */
