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
#include <sstream>
#include <nanobind/stl/string.h>

#include "Abstract/init.hpp"
#include "pyLIEF.hpp"

#include "LIEF/Abstract/hash.hpp"
#include "LIEF/Abstract/Relocation.hpp"

namespace LIEF::py {

template<>
void create<Relocation>(nb::module_& m) {
  nb::class_<Relocation, Object>(m, "Relocation",
      R"delim(
      Class which represents an abstracted Relocation
      )delim")

    .def_prop_rw("address",
        nb::overload_cast<>(&Relocation::address, nb::const_),
        nb::overload_cast<uint64_t>(&Relocation::address),
        "Relocation's address"_doc)

    .def_prop_rw("size",
        nb::overload_cast<>(&Relocation::size, nb::const_),
        nb::overload_cast<size_t>(&Relocation::size),
        "Relocation's size (in **bits**)"_doc)

    LIEF_DEFAULT_STR(Relocation);
}
}
