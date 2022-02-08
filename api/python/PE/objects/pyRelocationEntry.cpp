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
#include "pyPE.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/RelocationEntry.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (RelocationEntry::*)(void) const;

template<class T>
using setter_t = void (RelocationEntry::*)(T);


template<>
void create<RelocationEntry>(py::module& m) {
  py::class_<RelocationEntry, LIEF::Relocation>(m, "RelocationEntry",
      R"delim(
      Class which represents an entry of the PE relocation table.

      It extends the :class:`lief.Relocation` object to provide an uniform API across the file formats
      )delim")
    .def(py::init<>())

    .def_property("data",
        static_cast<getter_t<uint16_t>>(&RelocationEntry::data),
        static_cast<setter_t<uint16_t>>(&RelocationEntry::data),
        R"delim(
        Raw data of the relocation:

          * The **high** 4 bits store the relocation :attr:`~lief.PE.RelocationEntry.type`
          * The **low** 12 bits store the relocation offset (:attr:`~lief.PE.RelocationEntry.position`)
        )delim")

    .def_property("position",
        static_cast<getter_t<uint16_t>>(&RelocationEntry::position),
        static_cast<setter_t<uint16_t>>(&RelocationEntry::position),
        "Offset - relative to :attr:`~lief.PE.Relocation.virtual_address` - where the relocation occurs")

    .def_property("type",
        static_cast<getter_t<RELOCATIONS_BASE_TYPES>>(&RelocationEntry::type),
        static_cast<setter_t<RELOCATIONS_BASE_TYPES>>(&RelocationEntry::type),
        "Type of the relocation (see: " RST_CLASS_REF(lief.PE.RELOCATIONS_BASE_TYPES) ")")


    .def("__eq__", &RelocationEntry::operator==)
    .def("__ne__", &RelocationEntry::operator!=)
    .def("__hash__",
        [] (const RelocationEntry& relocation_entry) {
          return Hash::hash(relocation_entry);
        })

    .def("__str__", [] (const RelocationEntry& relocation)
        {
          std::ostringstream stream;
          stream << relocation;
          std::string str = stream.str();
          return str;
        });
}

}
}
