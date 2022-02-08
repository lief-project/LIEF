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
#include "LIEF/PE/Symbol.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (Symbol::*)(void) const;

template<class T>
using setter_t = void (Symbol::*)(T);

template<class T>
using no_const_getter = T (Symbol::*)(void);


template<>
void create<Symbol>(py::module& m) {
  py::class_<Symbol, LIEF::Symbol>(m, "Symbol")
    .def(py::init<>())

    .def_property("name",
        static_cast<getter_t<std::wstring>>      (&Symbol::wname),
        static_cast<setter_t<const std::string&>>(&Symbol::name))

    .def_property_readonly("section_number",
        &Symbol::section_number)

    .def_property_readonly("type",
        &Symbol::type)

    .def_property_readonly("base_type",
        &Symbol::base_type)

    .def_property_readonly("complex_type",
        &Symbol::complex_type)

    .def_property_readonly("storage_class",
        &Symbol::storage_class)

    .def_property_readonly("numberof_aux_symbols",
        &Symbol::numberof_aux_symbols)

    .def_property_readonly("section",
        static_cast<no_const_getter<Section*>>(&Symbol::section),
        py::return_value_policy::reference)

    .def_property_readonly("has_section",
        &Symbol::has_section,
        "``True`` if symbols are located in a section")

    .def("__eq__", &Symbol::operator==)
    .def("__ne__", &Symbol::operator!=)
    .def("__hash__",
        [] (const Symbol& symbol) {
          return Hash::hash(symbol);
        })


    .def("__str__", [] (const Symbol& symbol)
        {
          std::ostringstream stream;
          stream << symbol;
          std::string str = stream.str();
          return str;
        });
}

}
}
