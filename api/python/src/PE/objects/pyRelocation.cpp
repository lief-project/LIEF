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
#include "pyIterator.hpp"

#include "LIEF/PE/Relocation.hpp"
#include "LIEF/PE/RelocationEntry.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<Relocation>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Relocation, LIEF::Object> reloc(m, "Relocation",
      R"delim(
      Class which represents the *Base Relocation Block*
      Usually, we find this structure in the ``.reloc`` section
      )delim"_doc);

  init_ref_iterator<Relocation::it_entries>(reloc, "it_entries");

  reloc
    .def(nb::init<>())

    .def_prop_rw("virtual_address",
        nb::overload_cast<>(&Relocation::virtual_address, nb::const_),
        nb::overload_cast<uint32_t>(&Relocation::virtual_address),
        "The RVA for which the offset of the relocation entries (RelocationEntry) is added"_doc)

    .def_prop_rw("block_size",
        nb::overload_cast<>(&Relocation::block_size, nb::const_),
        nb::overload_cast<uint32_t>(&Relocation::block_size),
        R"delim(
        The total number of bytes in the base relocation block.
        ``block_size = sizeof(BaseRelocationBlock) + nb_of_relocs * sizeof(uint16_t = RelocationEntry)``
        )delim"_doc)

    .def_prop_ro("entries",
        nb::overload_cast<>(&Relocation::entries),
        "Iterator over the " RST_CLASS_REF(lief.PE.RelocationEntry) ""_doc)

    .def("add_entry",
        &Relocation::add_entry,
        "Add a new " RST_CLASS_REF(lief.PE.RelocationEntry) ""_doc,
        "new_entry"_a)

    LIEF_COPYABLE(Relocation)
    LIEF_DEFAULT_STR(Relocation);
}
}
