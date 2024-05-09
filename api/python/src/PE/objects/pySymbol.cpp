
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

#include "LIEF/PE/Symbol.hpp"
#include "LIEF/PE/Section.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/extra/stl/wstring.h>

namespace LIEF::PE::py {

template<>
void create<Symbol>(nb::module_& m) {
  nb::class_<Symbol, LIEF::Symbol>(m, "Symbol")
    .def(nb::init<>())

    .def_prop_rw("name",
        nb::overload_cast<>(&Symbol::wname, nb::const_),
        nb::overload_cast<std::string>(&Symbol::name))

    .def_prop_ro("section_number",
        &Symbol::section_number)

    .def_prop_ro("type",
        &Symbol::type)

    .def_prop_ro("base_type",
        &Symbol::base_type)

    .def_prop_ro("complex_type",
        &Symbol::complex_type)

    .def_prop_ro("storage_class",
        &Symbol::storage_class)

    .def_prop_ro("numberof_aux_symbols",
        &Symbol::numberof_aux_symbols)

    .def_prop_ro("section",
        nb::overload_cast<>(&Symbol::section),
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_section",
        &Symbol::has_section,
        "``True`` if symbols are located in a section"_doc)

    LIEF_DEFAULT_STR(Symbol);
}

}
