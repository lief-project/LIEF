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

#include "LIEF/ELF/SymbolVersion.hpp"
#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/SymbolVersionAux.hpp"
#include "LIEF/ELF/SymbolVersionAuxRequirement.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (SymbolVersion::*)(void) const;

template<class T>
using setter_t = void (SymbolVersion::*)(T);


template<>
void create<SymbolVersion>(py::module& m) {

  py::class_<SymbolVersion, LIEF::Object>(m, "SymbolVersion")
    .def(py::init<>(),"Default constructor")
    .def(py::init<uint16_t>(), "Constructor from :attr:`~lief.SymbolVersion.value`")

    .def_property_readonly_static("local",
        [] (const py::object&) {
          return SymbolVersion::local();
        },
        "Generate a *local* " RST_CLASS_REF(lief.ELF.SymbolVersion) "")

    .def_property_readonly_static("global_",
        [] (const py::object&) {
          return SymbolVersion::global();
        },
        "Generate a *global* " RST_CLASS_REF(lief.ELF.SymbolVersion) "")

    .def_property("value",
        static_cast<getter_t<uint16_t>>(&SymbolVersion::value),
        static_cast<setter_t<uint16_t>>(&SymbolVersion::value),
        R"delim(
        Value associated with the symbol.

        If the given SymbolVersion hasn't Auxiliary version:

        - `0` : The symbol is local
        - `1` : The symbol is global

        All other values are used for versions in the own object or in any of
        the dependencies. This is the version the symbol is tight to.
        )delim")

    .def_property_readonly("has_auxiliary_version",
        &SymbolVersion::has_auxiliary_version,
        "Check if this symbols has a " RST_CLASS_REF(lief.ELF.SymbolVersionAux) "")

    .def_property(
        "symbol_version_auxiliary",
        static_cast<SymbolVersionAux* (SymbolVersion::*)(void)>(&SymbolVersion::symbol_version_auxiliary),
        static_cast<void (SymbolVersion::*)(SymbolVersionAuxRequirement&)>(&SymbolVersion::symbol_version_auxiliary),
        R"delim(
        Return the :class:`~lief.ELF.SymbolVersionAux` associated with this version or None if not present.

        The value can be changed by assigning a :class:`~lief.ELF.SymbolVersionAuxRequirement` which
        must already exist in the :class:`~lief.ELF.SymbolVersionRequirement`. Once can use
        :meth:`~lief.ELF.SymbolVersionAuxRequirement.add_aux_requirement` to add a new
        :class:`~lief.ELF.SymbolVersionAuxRequirement`.
        )delim",
        py::return_value_policy::reference_internal)


    .def("__eq__", &SymbolVersion::operator==)
    .def("__ne__", &SymbolVersion::operator!=)
    .def("__hash__",
        [] (const SymbolVersion& sv) {
          return Hash::hash(sv);
        })

    .def("__str__",
        [] (const SymbolVersion& symbolVersion)
        {
          std::ostringstream stream;
          stream << symbolVersion;
          std::string str =  stream.str();
          return str;
        });
}

}
}
