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
#ifndef LIEF_MACHO_HEADER_H_
#define LIEF_MACHO_HEADER_H_

#include <iostream>
#include <set>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/Abstract/enums.hpp"

#include "LIEF/MachO/enums.hpp"

namespace LIEF {
namespace MachO {

namespace details {
struct mach_header_64;
struct mach_header;
}

//! Class that represents the Mach-O header
class LIEF_API Header : public Object {
  public:
  using flags_list_t = std::set<HEADER_FLAGS>;

  public:
  Header();
  Header(const details::mach_header_64& header);
  Header(const details::mach_header&    header);

  Header& operator=(const Header& copy);
  Header(const Header& copy);

  virtual ~Header();

  //! The Mach-O magic bytes. These bytes determine whether it is
  //! a 32 bits Mach-O, a 64 bits Mach-O files etc.
  MACHO_TYPES magic() const;

  //! The CPU architecture targeted by this binary
  CPU_TYPES cpu_type() const;

  //! Return the CPU subtype supported by the Mach-O binary.
  //! For ARM architectures, this value could represent the minimum version
  //! for which the Mach-O binary has been compiled for.
  uint32_t cpu_subtype() const;

  //! Return the type of the Mach-O file (executable, object, shared library, ...)
  FILE_TYPES file_type() const;

  //! Return the HEADER_FLAGS as a std::set
  flags_list_t flags_list() const;

  //! Check if the given HEADER_FLAGS is present in the header's flags
  bool has(HEADER_FLAGS flag) const;

  //! Number of LoadCommand present in the Mach-O binary
  uint32_t nb_cmds() const;

  //! The size of **all** the LoadCommand
  uint32_t sizeof_cmds() const;

  //! Header flags (cf. HEADER_FLAGS)
  //!
  //! @see flags_list
  uint32_t flags() const;

  //! According to the official documentation, a reserved value
  uint32_t reserved() const;

  void add(HEADER_FLAGS flag);

  //! LIEF abstract object type
  OBJECT_TYPES abstract_object_type() const;

  std::pair<ARCHITECTURES, std::set<MODES>> abstract_architecture() const;

  //! LIEF abstract endiannes
  ENDIANNESS abstract_endianness() const;

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

  void accept(Visitor& visitor) const override;

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
