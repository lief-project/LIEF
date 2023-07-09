/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<RelocationEntry>(nb::module_& m) {
  nb::class_<RelocationEntry, LIEF::Relocation>(m, "RelocationEntry",
      R"delim(
      Class which represents an entry of the PE relocation table.

      It extends the :class:`lief.Relocation` object to provide an uniform API across the file formats
      )delim"_doc)
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
        nb::overload_cast<RELOCATIONS_BASE_TYPES>(&RelocationEntry::type),
        "Type of the relocation (see: " RST_CLASS_REF(lief.PE.RELOCATIONS_BASE_TYPES) ")"_doc)

    LIEF_DEFAULT_STR(LIEF::PE::RelocationEntry);
}
}
