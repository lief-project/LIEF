/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#include "COFF/pyCOFF.hpp"

#include "LIEF/COFF/Relocation.hpp"
#include "LIEF/COFF/Symbol.hpp"
#include "LIEF/COFF/Section.hpp"

#include "enums_wrapper.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

namespace LIEF::COFF::py {

template<>
void create<Relocation>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Relocation, LIEF::Relocation> relocation(m, "Relocation");

  #define ENTRY(X) .value(to_string(Relocation::TYPE::X), Relocation::TYPE::X)
  enum_<Relocation::TYPE>(relocation, "TYPE")
    ENTRY(UNKNOWN)

    ENTRY(AMD64_ABSOLUTE)
    ENTRY(AMD64_ADDR32)
    ENTRY(AMD64_ADDR32NB)
    ENTRY(AMD64_ADDR64)
    ENTRY(AMD64_PAIR)
    ENTRY(AMD64_REL32)
    ENTRY(AMD64_REL32_1)
    ENTRY(AMD64_REL32_2)
    ENTRY(AMD64_REL32_3)
    ENTRY(AMD64_REL32_4)
    ENTRY(AMD64_REL32_5)
    ENTRY(AMD64_SECREL)
    ENTRY(AMD64_SECREL7)
    ENTRY(AMD64_SECTION)
    ENTRY(AMD64_SREL32)
    ENTRY(AMD64_SSPAN32)
    ENTRY(AMD64_TOKEN)

    ENTRY(ARM64_ABSOLUTE)
    ENTRY(ARM64_ADDR32)
    ENTRY(ARM64_ADDR32NB)
    ENTRY(ARM64_ADDR64)
    ENTRY(ARM64_BRANCH14)
    ENTRY(ARM64_BRANCH19)
    ENTRY(ARM64_BRANCH26)
    ENTRY(ARM64_PAGEBASE_REL21)
    ENTRY(ARM64_PAGEOFFSET_12A)
    ENTRY(ARM64_PAGEOFFSET_12L)
    ENTRY(ARM64_REL21)
    ENTRY(ARM64_REL32)
    ENTRY(ARM64_SECREL)
    ENTRY(ARM64_SECREL_HIGH12A)
    ENTRY(ARM64_SECREL_LOW12A)
    ENTRY(ARM64_SECREL_LOW12L)
    ENTRY(ARM64_SECTION)
    ENTRY(ARM64_TOKEN)

    ENTRY(ARM_ABSOLUTE)
    ENTRY(ARM_ADDR32)
    ENTRY(ARM_ADDR32NB)
    ENTRY(ARM_BLX11)
    ENTRY(ARM_BLX23T)
    ENTRY(ARM_BLX24)
    ENTRY(ARM_BRANCH11)
    ENTRY(ARM_BRANCH20T)
    ENTRY(ARM_BRANCH24)
    ENTRY(ARM_BRANCH24T)
    ENTRY(ARM_MOV32A)
    ENTRY(ARM_MOV32T)
    ENTRY(ARM_PAIR)
    ENTRY(ARM_REL32)
    ENTRY(ARM_SECREL)
    ENTRY(ARM_SECTION)
    ENTRY(ARM_TOKEN)

    ENTRY(I386_ABSOLUTE)
    ENTRY(I386_DIR16)
    ENTRY(I386_DIR32)
    ENTRY(I386_DIR32NB)
    ENTRY(I386_REL16)
    ENTRY(I386_REL32)
    ENTRY(I386_SECREL)
    ENTRY(I386_SECREL7)
    ENTRY(I386_SECTION)
    ENTRY(I386_SEG12)
    ENTRY(I386_TOKEN)

    ENTRY(MIPS_ABSOLUTE)
    ENTRY(MIPS_GPREL)
    ENTRY(MIPS_JMPADDR)
    ENTRY(MIPS_JMPADDR16)
    ENTRY(MIPS_LITERAL)
    ENTRY(MIPS_PAIR)
    ENTRY(MIPS_REFHALF)
    ENTRY(MIPS_REFHI)
    ENTRY(MIPS_REFLO)
    ENTRY(MIPS_REFWORD)
    ENTRY(MIPS_REFWORDNB)
    ENTRY(MIPS_SECREL)
    ENTRY(MIPS_SECRELHI)
    ENTRY(MIPS_SECRELLO)
    ENTRY(MIPS_SECTION)
  ;
  #undef ENTRY

  relocation
    .def_prop_ro("symbol_idx", &Relocation::symbol_idx,
      "Symbol index associated with this relocation"_doc
    )
    .def_prop_ro("symbol", nb::overload_cast<>(&Relocation::symbol),
      "Symbol associated with the relocation (if any)"_doc
    )
    .def_prop_ro("type", &Relocation::type,
      "Type of the relocation"_doc
    )
    .def_prop_ro("section", nb::overload_cast<>(&Relocation::section),
      "Section in which the relocation takes place"_doc
    )
    LIEF_DEFAULT_STR(Relocation);
}

}
