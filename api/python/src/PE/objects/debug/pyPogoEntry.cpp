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
#include "pySafeString.hpp"

#include "LIEF/PE/debug/PogoEntry.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<PogoEntry>(nb::module_& m) {
  nb::class_<PogoEntry, Object>(m, "PogoEntry")
    .def(nb::init<>())

    .def_prop_rw("name",
        [] (const PogoEntry& obj) {
          return LIEF::py::safe_string(obj.name());
        },
        nb::overload_cast<std::string>(&PogoEntry::name))

    .def_prop_rw("start_rva",
        nb::overload_cast<>(&PogoEntry::start_rva, nb::const_),
        nb::overload_cast<uint32_t>(&PogoEntry::start_rva))

    .def_prop_rw("size",
        nb::overload_cast<>(&PogoEntry::size, nb::const_),
        nb::overload_cast<uint32_t>(&PogoEntry::size))

    LIEF_COPYABLE(PogoEntry)
    LIEF_DEFAULT_STR(PogoEntry);
}
}
