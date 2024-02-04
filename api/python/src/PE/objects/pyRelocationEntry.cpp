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
#include "PE/pyPE.hpp"

#include "LIEF/PE/RelocationEntry.hpp"

#include "enums_wrapper.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<RelocationEntry>(nb::module_& m) {
  nb::class_<RelocationEntry, LIEF::Relocation> entry(m, "RelocationEntry",
      R"delim(
      Class which represents an entry of the PE relocation table.

      It extends the :class:`lief.Relocation` object to provide an uniform API across the file formats.
      )delim"_doc);

  #define ENTRY(X) .value(to_string(RelocationEntry::BASE_TYPES::X), RelocationEntry::BASE_TYPES::X)
  enum_<RelocationEntry::BASE_TYPES>(entry, "BASE_TYPES")
    ENTRY(UNKNOWN)
    ENTRY(ABS)
    ENTRY(HIGH)
    ENTRY(LOW)
    ENTRY(HIGHLOW)
    ENTRY(HIGHADJ)
    ENTRY(MIPS_JMPADDR)
    ENTRY(ARM_MOV32A)
    ENTRY(ARM_MOV32)
    ENTRY(RISCV_HI20)
    ENTRY(SECTION)
    ENTRY(REL)
    ENTRY(ARM_MOV32T)
    ENTRY(THUMB_MOV32)
    ENTRY(RISCV_LOW12I)
    ENTRY(RISCV_LOW12S)
    ENTRY(MIPS_JMPADDR16)
    ENTRY(IA64_IMM64)
    ENTRY(DIR64)
    ENTRY(HIGH3ADJ);
  #undef ENTRY

  entry
    .def(nb::init<>())
    .def_prop_rw("data",
        nb::overload_cast<>(&RelocationEntry::data, nb::const_),
        nb::overload_cast<uint16_t>(&RelocationEntry::data),
        R"delim(
        Raw data of the relocation:

          * The **high** 4 bits store the relocation :attr:`~lief.PE.RelocationEntry.type`
          * The **low** 12 bits store the relocation offset (:attr:`~lief.PE.RelocationEntry.position`)
        )delim"_doc)

    .def_prop_rw("position",
        nb::overload_cast<>(&RelocationEntry::position, nb::const_),
        nb::overload_cast<uint16_t>(&RelocationEntry::position),
        "Offset - relative to :attr:`~lief.PE.Relocation.virtual_address` - where the relocation occurs"_doc)

    .def_prop_rw("type",
        nb::overload_cast<>(&RelocationEntry::type, nb::const_),
        nb::overload_cast<RelocationEntry::BASE_TYPES>(&RelocationEntry::type),
        "Type of the relocation"_doc)

    LIEF_DEFAULT_STR(RelocationEntry);
}
}
