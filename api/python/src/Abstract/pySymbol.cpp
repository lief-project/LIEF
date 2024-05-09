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
#include "pySafeString.hpp"

#include "LIEF/Abstract/Symbol.hpp"

namespace LIEF::py {

template<>
void create<Symbol>(nb::module_& m) {
  nb::class_<Symbol, Object>(m, "Symbol",
      R"delim(
      This class represents a symbol in an executable format.
      )delim"_doc)

    .def_prop_rw("name",
        [] (const Symbol& obj) {
          return safe_string(obj.name());
        },
        nb::overload_cast<std::string>(&Symbol::name),
        "Symbol's name"_doc)

    .def_prop_rw("value",
        nb::overload_cast<>(&Symbol::value, nb::const_),
        nb::overload_cast<uint64_t>(&Symbol::value),
        "Symbol's value"_doc)

    .def_prop_rw("size",
        nb::overload_cast<>(&Symbol::size, nb::const_),
        nb::overload_cast<uint64_t>(&Symbol::size),
        "Symbol's size"_doc)

    LIEF_DEFAULT_STR(Symbol);
}
}
