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
#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

#include "LIEF/MachO/Section.hpp"
#include "LIEF/MachO/Symbol.hpp"
#include "LIEF/MachO/BindingInfo.hpp"
#include "LIEF/MachO/ExportInfo.hpp"

#include "pyIterator.hpp"
#include "MachO/pyMachO.hpp"
#include "enums_wrapper.hpp"

namespace LIEF::MachO::py {

template<>
void create<Symbol>(nb::module_& m) {

  nb::class_<Symbol, LIEF::Symbol> symbol(m, "Symbol",
      R"delim(
      Class that represents a Symbol in a Mach-O file.

      A Mach-O symbol can come from:

      1. The symbols command (LC_SYMTAB / SymbolCommand)
      2. The Dyld Export trie
      3. The Dyld Symbol bindings
      )delim"_doc);

  enum_<Symbol::CATEGORY>(symbol, "CATEGORY")
    .value("NONE",           Symbol::CATEGORY::NONE)
    .value("LOCAL",          Symbol::CATEGORY::LOCAL)
    .value("EXTERNAL",       Symbol::CATEGORY::EXTERNAL)
    .value("UNDEFINED",      Symbol::CATEGORY::UNDEFINED)
    .value("INDIRECT_ABS",   Symbol::CATEGORY::INDIRECT_ABS)
    .value("INDIRECT_LOCAL", Symbol::CATEGORY::INDIRECT_LOCAL);

  enum_<Symbol::ORIGIN>(symbol, "ORIGIN")
    .value("UNKNOWN",        Symbol::ORIGIN::UNKNOWN)
    .value("DYLD_EXPORT",    Symbol::ORIGIN::DYLD_EXPORT)
    .value("DYLD_BIND",      Symbol::ORIGIN::DYLD_BIND)
    .value("LC_SYMTAB",      Symbol::ORIGIN::LC_SYMTAB)
  ;

  enum_<Symbol::TYPE>(symbol, "TYPE")
    .value("UNDEFINED",    Symbol::TYPE::UNDEFINED)
    .value("ABSOLUTE_SYM", Symbol::TYPE::ABSOLUTE_SYM)
    .value("SECTION",      Symbol::TYPE::SECTION)
    .value("PREBOUND",     Symbol::TYPE::PREBOUND)
    .value("INDIRECT",     Symbol::TYPE::INDIRECT)
  ;
  symbol
    .def(nb::init<>())

    .def_prop_ro("demangled_name",
        &Symbol::demangled_name,
        "Symbol's unmangled name"_doc)

    .def_prop_ro("category",
        &Symbol::category,
        "Category of the symbol according to the `LC_DYSYMTAB` command"_doc)

    .def_prop_rw("raw_type",
        nb::overload_cast<>(&Symbol::raw_type, nb::const_),
        nb::overload_cast<uint8_t>(&Symbol::raw_type),
        R"doc(
        Raw value of ``nlist_xx.n_type``
        )doc"_doc
    )

    .def_prop_ro("type",
        nb::overload_cast<>(&Symbol::type, nb::const_),
        R"doc(
        Type as defined by ``nlist_xx.n_type & N_TYPE``
        )doc"_doc)

    .def_prop_rw("numberof_sections",
        nb::overload_cast<>(&Symbol::numberof_sections, nb::const_),
        nb::overload_cast<uint8_t>(&Symbol::numberof_sections),
        R"delim(
        It returns the number of sections in which this symbol can be found.
        If the symbol can't be found in any section, it returns 0 (NO_SECT)
        )delim"_doc)

    .def_prop_rw("description",
        nb::overload_cast<>(&Symbol::description, nb::const_),
        nb::overload_cast<uint16_t>(&Symbol::description),
        "Return information about the symbol"_doc)

    .def_prop_ro("has_export_info",
        &Symbol::has_export_info,
        "``True`` if the symbol has an " RST_CLASS_REF(lief.MachO.ExportInfo) " associated with"_doc)

    .def_prop_ro("origin",
        &Symbol::origin,
        "Return the " RST_CLASS_REF(lief.MachO.Symbol.ORIGIN) " of this symbol"_doc)

    .def_prop_ro("export_info",
        nb::overload_cast<>(&Symbol::export_info),
        "" RST_CLASS_REF(lief.MachO.ExportInfo) " associated with the symbol if any, or None"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("has_binding_info",
        &Symbol::has_binding_info,
        "``True`` if the symbol has an " RST_CLASS_REF(lief.MachO.BindingInfo) " associated with"_doc)

    .def_prop_ro("binding_info",
        nb::overload_cast<>(&Symbol::binding_info),
        "" RST_CLASS_REF(lief.MachO.BindingInfo) " associated with the symbol if any, or None"_doc,
        nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(Symbol);
}
}
