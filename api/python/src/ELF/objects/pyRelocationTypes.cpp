/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

#include "ELF/pyELF.hpp"
#include "enums_wrapper.hpp"

#include "LIEF/ELF/Relocation.hpp"

namespace LIEF::ELF::py {

void init_relocation_types(nb::class_<Relocation, LIEF::Relocation>& m) {

  #define ELF_RELOC(X, _) .value(to_string(Relocation::TYPE::X), Relocation::TYPE::X)
  enum_<Relocation::TYPE>(m, "TYPE")
    #include "LIEF/ELF/Relocations/x86_64.def"
    #include "LIEF/ELF/Relocations/AArch64.def"
    #include "LIEF/ELF/Relocations/ARM.def"
    #include "LIEF/ELF/Relocations/Hexagon.def"
    #include "LIEF/ELF/Relocations/i386.def"
    #include "LIEF/ELF/Relocations/LoongArch.def"
    #include "LIEF/ELF/Relocations/Mips.def"
    #include "LIEF/ELF/Relocations/PowerPC.def"
    #include "LIEF/ELF/Relocations/PowerPC64.def"
    #include "LIEF/ELF/Relocations/Sparc.def"
    #include "LIEF/ELF/Relocations/SystemZ.def"
  ;
  #undef ELF_RELOC
}

}
