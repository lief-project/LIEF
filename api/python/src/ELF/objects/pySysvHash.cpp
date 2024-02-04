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
#include <nanobind/stl/vector.h>

#include "ELF/pyELF.hpp"

#include "LIEF/ELF/SysvHash.hpp"

namespace LIEF::ELF::py {

template<>
void create<SysvHash>(nb::module_& m) {
  nb::class_<SysvHash, LIEF::Object>(m, "SysvHash",
    R"delim(
    Class which represents the SYSV hash for the symbols resolution

    References:

      * http://www.linker-aliens.org/blogs/ali/entry/gnu_hash_elf_sections/
      * https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-48031.html
    )delim"_doc)
    .def(nb::init<>())

    .def_prop_ro("nbucket",
      &SysvHash::nbucket,
      "Return the number of buckets"_doc)

    .def_prop_rw("nchain",
      nb::overload_cast<>(&SysvHash::nchain, nb::const_),
      nb::overload_cast<uint32_t>(&SysvHash::nchain),
      "Return the number of *chains* (symbol table index)"_doc)

    .def_prop_ro("buckets",
      &SysvHash::buckets,
      "Buckets values"_doc,
      nb::rv_policy::reference_internal)

    .def_prop_ro("chains",
      &SysvHash::chains,
      "Chains values"_doc,
      nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(SysvHash);
}
}
