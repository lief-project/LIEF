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
#include <string>
#include <sstream>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/Section.hpp"
#include "LIEF/MachO/Symbol.hpp"

#include "pyIterators.hpp"
#include "pyMachO.hpp"

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (Symbol::*)(void) const;

template<class T>
using setter_t = void (Symbol::*)(T);


template<>
void create<Symbol>(py::module& m) {

  py::class_<Symbol, LIEF::Symbol> symbol(m, "Symbol",
      R"delim(
      Class that represents a Symbol in a Mach-O file.

      A Mach-O symbol can come from:

      1. The symbols command (LC_SYMTAB / SymbolCommand)
      2. The Dyld Export trie
      3. The Dyld Symbol bindings
      )delim");

  py::enum_<Symbol::CATEGORY>(symbol, "TOOLS")
    .value("NONE",           Symbol::CATEGORY::NONE)
    .value("LOCAL",          Symbol::CATEGORY::LOCAL)
    .value("EXTERNAL",       Symbol::CATEGORY::EXTERNAL)
    .value("UNDEFINED",      Symbol::CATEGORY::UNDEFINED)
    .value("INDIRECT_ABS",   Symbol::CATEGORY::INDIRECT_ABS)
    .value("INDIRECT_LOCAL", Symbol::CATEGORY::INDIRECT_LOCAL);

  symbol
    .def(py::init<>())

    .def_property_readonly("demangled_name",
        &Symbol::demangled_name,
        "Symbol's unmangled name")

    .def_property("type",
        static_cast<getter_t<uint8_t>>(&Symbol::type),
        static_cast<setter_t<uint8_t>>(&Symbol::type))

    .def_property("numberof_sections",
        static_cast<getter_t<uint8_t>>(&Symbol::numberof_sections),
        static_cast<setter_t<uint8_t>>(&Symbol::numberof_sections),
        R"delim(
        It returns the number of sections in which this symbol can be found.
        If the symbol can't be found in any section, it returns 0 (NO_SECT)
        )delim")

    .def_property("description",
        static_cast<getter_t<uint16_t>>(&Symbol::description),
        static_cast<setter_t<uint16_t>>(&Symbol::description),
        "Return information about the symbol (:class:`~lief.MachO.SYMBOL_DESCRIPTIONS`)")

    .def_property_readonly("has_export_info",
        &Symbol::has_export_info,
        "``True`` if the symbol has an " RST_CLASS_REF(lief.MachO.ExportInfo) " associated with")

    .def_property_readonly("origin",
        &Symbol::origin,
        "Return the " RST_CLASS_REF(lief.MachO.SYMBOL_ORIGINS) " of this symbol")

    .def_property_readonly("export_info",
        static_cast<ExportInfo* (Symbol::*)(void)>(&Symbol::export_info),
        "" RST_CLASS_REF(lief.MachO.ExportInfo) " associated with the symbol if any, or None",
        py::return_value_policy::reference)

    .def_property_readonly("has_binding_info",
        &Symbol::has_binding_info,
        "``True`` if the symbol has an " RST_CLASS_REF(lief.MachO.BindingInfo) " associated with")

    .def_property_readonly("binding_info",
        static_cast<BindingInfo* (Symbol::*)(void)>(&Symbol::binding_info),
        "" RST_CLASS_REF(lief.MachO.BindingInfo) " associated with the symbol if any, or None",
        py::return_value_policy::reference)

    .def("__eq__", &Symbol::operator==)
    .def("__ne__", &Symbol::operator!=)
    .def("__hash__",
        [] (const Symbol& symbol) {
          return Hash::hash(symbol);
        })


    .def("__str__",
        [] (const Symbol& symbol) {
          std::ostringstream stream;
          stream << symbol;
          std::string str =  stream.str();
          return str;
        });

}

}
}



