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
#include "pyELF.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/SymbolVersionAux.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (SymbolVersionAux::*)(void) const;

template<class T>
using setter_t = void (SymbolVersionAux::*)(T);

template<>
void create<SymbolVersionAux>(py::module& m) {

  py::class_<SymbolVersionAux, LIEF::Object>(m, "SymbolVersionAux",
      "Class which represents an Auxiliary Symbol version")

    .def_property("name",
        [] (const SymbolVersionAux& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<const std::string&>>(&SymbolVersionAux::name),
        "Symbol's name (e.g. ``GLIBC_2.2.5``)")

    .def("__eq__", &SymbolVersionAux::operator==)
    .def("__ne__", &SymbolVersionAux::operator!=)
    .def("__hash__",
        [] (const SymbolVersionAux& sva) {
          return Hash::hash(sva);
        })

    .def("__str__",
        [] (const SymbolVersionAux& symbolVersionAux)
        {
          std::ostringstream stream;
          stream << symbolVersionAux;
          std::string str =  stream.str();
          return str;
        });
}

}
}
