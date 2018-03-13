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
#ifndef LIEF_MACHO_HEADER_H_
#define LIEF_MACHO_HEADER_H_

#include <iostream>
#include <set>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/Abstract/enums.hpp"

#include "LIEF/MachO/Structures.hpp"

namespace LIEF {
namespace MachO {
class LIEF_API Header : public Object {
  public:
    Header(void);
    Header(const mach_header_64 *header);
    Header(const mach_header    *header);

    Header& operator=(const Header& copy);
    Header(const Header& copy);

    virtual ~Header(void);

    MACHO_TYPES            magic(void) const;
    CPU_TYPES              cpu_type(void) const;
    uint32_t               cpu_subtype(void) const;
    FILE_TYPES             file_type(void) const;
    std::set<HEADER_FLAGS> flags_list(void) const;
    bool                   has(HEADER_FLAGS flag) const;
    uint32_t               nb_cmds(void) const;
    uint32_t               sizeof_cmds(void) const;
    uint32_t               flags(void) const;
    uint32_t               reserved(void) const;

    void add(HEADER_FLAGS flag);

    //! @brief LIEF abstract object type
    OBJECT_TYPES abstract_object_type(void) const;

    std::pair<ARCHITECTURES, std::set<MODES>> abstract_architecture(void) const;

    //! @brief LIEF abstract endiannes
    ENDIANNESS abstract_endianness(void) const;

    void magic(MACHO_TYPES magic);
    void cpu_type(CPU_TYPES cputype);
    void cpu_subtype(uint32_t cpusubtype);
    void file_type(FILE_TYPES filetype);
    void nb_cmds(uint32_t ncmds);
    void sizeof_cmds(uint32_t sizeofcmds);
    void flags(uint32_t flags);
    void remove(HEADER_FLAGS flag);
    void reserved(uint32_t reserved);

    Header& operator+=(HEADER_FLAGS c);
    Header& operator-=(HEADER_FLAGS c);

    bool operator==(const Header& rhs) const;
    bool operator!=(const Header& rhs) const;

    virtual void accept(Visitor& visitor) const override;

    LIEF_API friend std::ostream& operator<<(std::ostream& os, const Header& hdr);

  private:
    MACHO_TYPES magic_;
    CPU_TYPES   cputype_;
    uint32_t    cpusubtype_;
    FILE_TYPES  filetype_;
    uint32_t    ncmds_;
    uint32_t    sizeofcmds_;
    uint32_t    flags_;
    uint32_t    reserved_;
};

}
}
#endif
