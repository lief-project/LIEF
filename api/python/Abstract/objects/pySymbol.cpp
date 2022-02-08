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
#include "pyAbstract.hpp"
#include "LIEF/Abstract/Symbol.hpp"

#include <string>
#include <sstream>

namespace LIEF {

template<class T>
using getter_t = T (Symbol::*)(void) const;

template<class T>
using setter_t = void (Symbol::*)(T);

template<>
void create<Symbol>(py::module& m) {

  py::class_<Symbol, Object>(m, "Symbol",
      R"delim(
      This class represents a symbol in an executable format.
      )delim")
    .def(py::init())

    .def_property("name",
        [] (const Symbol& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<const std::string&>>(&Symbol::name),
        "Symbol's name")

    .def_property("value",
        static_cast<getter_t<uint64_t>>(&Symbol::value),
        static_cast<setter_t<uint64_t>>(&Symbol::value),
        "Symbol's value")

    .def_property("size",
        static_cast<getter_t<uint64_t>>(&Symbol::size),
        static_cast<setter_t<uint64_t>>(&Symbol::size),
        "Symbol's size")

    .def("__str__",
        [] (const Symbol& symbol)
        {
          std::ostringstream stream;
          stream << symbol;
          std::string str = stream.str();
          return str;
        });
}

}
