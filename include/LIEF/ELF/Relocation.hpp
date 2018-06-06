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
#ifndef LIEF_ELF_RELOCATION_H_
#define LIEF_ELF_RELOCATION_H_

#include <string>
#include <map>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/Abstract/Relocation.hpp"

#include "LIEF/ELF/Structures.hpp"
#include "LIEF/ELF/Symbol.hpp"

namespace LIEF {
namespace ELF {

class Parser;
class Binary;
class Builder;

class LIEF_API Relocation : public LIEF::Relocation {

  friend class Parser;
  friend class Binary;
  friend class Builder;

  public:
    Relocation(const Elf32_Rel*  header);
    Relocation(const Elf32_Rela* header);
    Relocation(const Elf64_Rel*  header);
    Relocation(const Elf64_Rela* header);
    Relocation(uint64_t address, uint32_t type = 0, int64_t addend = 0, bool isRela = false);

    template<class T, typename = typename std::enable_if<std::is_enum<T>::value>::type>
    Relocation(uint64_t address, T type, int64_t addend = 0, bool isRela = false) :
      Relocation{address, static_cast<uint32_t>(type), addend, isRela}
    {}

    Relocation(void);
    virtual ~Relocation(void);

    Relocation& operator=(Relocation other);
    Relocation(const Relocation& other);
    void swap(Relocation& other);

    //uint64_t address(void) const;
    int64_t  addend(void) const;
    uint32_t type(void) const;
    bool     is_rela(void) const;
    bool     is_rel(void) const;
    uint32_t info(void) const;
    ARCH architecture(void) const;
    RELOCATION_PURPOSES purpose(void) const;

    //! @brief Return the **bit** size of the value to patch
    //!
    //! Return -1 if it fails
    virtual size_t size(void) const override;

    bool          has_symbol(void) const;
    Symbol&       symbol(void);
    const Symbol& symbol(void) const;

    //! True if the relocation has a section associated
    bool           has_section(void) const;

    //! Section associated with this relocation
    Section&       section(void);
    const Section& section(void) const;

    //void address(uint64_t address);
    void addend(int64_t addend);
    void type(uint32_t type);
    void purpose(RELOCATION_PURPOSES purpose);
    void info(uint32_t v);

    virtual void accept(Visitor& visitor) const override;

    bool operator==(const Relocation& rhs) const;
    bool operator!=(const Relocation& rhs) const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const Relocation& entry);

  private:
    uint32_t            type_;
    int64_t             addend_;
    bool                isRela_;
    Symbol*             symbol_{nullptr};
    ARCH                architecture_;
    RELOCATION_PURPOSES purpose_;
    Section*            section_{nullptr};
    uint32_t            info_;
};



}
}
#endif /* _ELF_RELOCATION_H_ */
