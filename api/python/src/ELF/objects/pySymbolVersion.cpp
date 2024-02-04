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
#include "ELF/pyELF.hpp"

#include "LIEF/ELF/SymbolVersion.hpp"
#include "LIEF/ELF/SymbolVersionAux.hpp"
#include "LIEF/ELF/SymbolVersionAuxRequirement.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::ELF::py {

template<>
void create<SymbolVersion>(nb::module_& m) {
  nb::class_<SymbolVersion, LIEF::Object>(m, "SymbolVersion")
    .def(nb::init<>(),"Default constructor")
    .def(nb::init<uint16_t>(), "Constructor from :attr:`~lief.SymbolVersion.value`"_doc)

    .def_prop_ro_static("local",
        [] (const nb::object&) {
          return SymbolVersion::local();
        },
        "Generate a *local* " RST_CLASS_REF(lief.ELF.SymbolVersion) ""_doc)

    .def_prop_ro_static("global_",
        [] (const nb::object&) {
          return SymbolVersion::global();
        },
        "Generate a *global* " RST_CLASS_REF(lief.ELF.SymbolVersion) ""_doc)

    .def_prop_rw("value",
        nb::overload_cast<>(&SymbolVersion::value, nb::const_),
        nb::overload_cast<uint16_t>(&SymbolVersion::value),
        R"delim(
        Value associated with the symbol.

        If the given SymbolVersion hasn't Auxiliary version:

        - `0` : The symbol is local
        - `1` : The symbol is global

        All other values are used for versions in the own object or in any of
        the dependencies. This is the version the symbol is tight to.
        )delim"_doc)

    .def_prop_ro("has_auxiliary_version",
        &SymbolVersion::has_auxiliary_version,
        "Check if this symbols has a " RST_CLASS_REF(lief.ELF.SymbolVersionAux) ""_doc)

    .def_prop_rw(
        "symbol_version_auxiliary",
        nb::overload_cast<>(&SymbolVersion::symbol_version_auxiliary),
        nb::overload_cast<SymbolVersionAuxRequirement&>(&SymbolVersion::symbol_version_auxiliary),
        R"delim(
        Return the :class:`~lief.ELF.SymbolVersionAux` associated with this version or None if not present.

        The value can be changed by assigning a :class:`~lief.ELF.SymbolVersionAuxRequirement` which
        must already exist in the :class:`~lief.ELF.SymbolVersionRequirement`. Once can use
        :meth:`~lief.ELF.SymbolVersionAuxRequirement.add_aux_requirement` to add a new
        :class:`~lief.ELF.SymbolVersionAuxRequirement`.
        )delim"_doc,
        nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(SymbolVersion);

}
}
