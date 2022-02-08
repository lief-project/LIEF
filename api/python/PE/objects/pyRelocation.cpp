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
#include "pyIterators.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/Relocation.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (Relocation::*)(void) const;

template<class T>
using setter_t = void (Relocation::*)(T);

template<class T>
using it_t = T (Relocation::*)(void);

template<>
void create<Relocation>(py::module& m) {
  py::class_<Relocation, LIEF::Object> reloc(m, "Relocation",
      R"delim(
      Class which represents the *Base Relocation Block*
      Usually, we find this structure in the ``.reloc`` section
      )delim");

  init_ref_iterator<Relocation::it_entries>(reloc, "it_entries");

  reloc
    .def(py::init<>())

    .def_property("virtual_address",
        static_cast<getter_t<uint32_t>>(&Relocation::virtual_address),
        static_cast<setter_t<uint32_t>>(&Relocation::virtual_address),
        "The RVA for which the offset of the relocation entries (RelocationEntry) is added")

    .def_property("block_size",
        static_cast<getter_t<uint32_t>>(&Relocation::block_size),
        static_cast<setter_t<uint32_t>>(&Relocation::block_size),
        R"delim(
        The total number of bytes in the base relocation block.
        ``block_size = sizeof(BaseRelocationBlock) + nb_of_relocs * sizeof(uint16_t = RelocationEntry)``
        )delim")

    .def_property_readonly("entries",
        static_cast<it_t<Relocation::it_entries>>(&Relocation::entries),
        "Iterator over the " RST_CLASS_REF(lief.PE.RelocationEntry) "")

    .def("add_entry",
        &Relocation::add_entry,
        "Add a new " RST_CLASS_REF(lief.PE.RelocationEntry) "",
        "new_entry"_a)


    .def("__eq__", &Relocation::operator==)
    .def("__ne__", &Relocation::operator!=)
    .def("__hash__",
        [] (const Relocation& relocation) {
          return Hash::hash(relocation);
        })

    .def("__str__", [] (const Relocation& relocation)
        {
          std::ostringstream stream;
          stream << relocation;
          std::string str = stream.str();
          return str;
        });
}
}
}
