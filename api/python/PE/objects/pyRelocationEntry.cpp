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
#include "pyPE.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/RelocationEntry.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (RelocationEntry::*)(void) const;

template<class T>
using setter_t = void (RelocationEntry::*)(T);

void init_PE_RelocationEntry_class(py::module& m) {
  py::class_<RelocationEntry, LIEF::Relocation>(m, "RelocationEntry")
    .def(py::init<>())

    .def_property("data",
        static_cast<getter_t<uint16_t>>(&RelocationEntry::data),
        static_cast<setter_t<uint16_t>>(&RelocationEntry::data),
        "Raw data of the relocation:\n\n"

        "\t\t * The **high** 4 bits store the relocation :attr:`~lief.PE.RelocationEntry.type`\n\n"
        "\t\t * The **low** 12 bits store the relocation offset (:attr:`~lief.PE.RelocationEntry.position`)\n\n"
        )

    .def_property("position",
        static_cast<getter_t<uint16_t>>(&RelocationEntry::position),
        static_cast<setter_t<uint16_t>>(&RelocationEntry::position),
        "Offset - relative to :attr:`~lief.PE.Relocation.virtual_address` - where the relocation occurs")

    .def_property("type",
        static_cast<getter_t<RELOCATIONS_BASE_TYPES>>(&RelocationEntry::type),
        static_cast<setter_t<RELOCATIONS_BASE_TYPES>>(&RelocationEntry::type),
        "Type of the relocation")


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
