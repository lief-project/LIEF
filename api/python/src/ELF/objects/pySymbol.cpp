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
#include "pyIterator.hpp"
#include "enums_wrapper.hpp"

#include "LIEF/ELF/Symbol.hpp"
#include "LIEF/ELF/SymbolVersion.hpp"
#include "LIEF/ELF/Section.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::ELF::py {

template<>
void create<Symbol>(nb::module_& m) {

  nb::class_<Symbol, LIEF::Symbol> sym(m, "Symbol",
    R"delim(
    Class which represents an ELF symbol
    )delim"_doc);

  #define ENTRY(X) .value(to_string(Symbol::BINDING::X), Symbol::BINDING::X)
  enum_<Symbol::BINDING>(sym, "BINDING")
    ENTRY(LOCAL)
    ENTRY(GLOBAL)
    ENTRY(WEAK)
    ENTRY(GNU_UNIQUE)
  ;
  #undef ENTRY

  #define ENTRY(X) .value(to_string(Symbol::TYPE::X), Symbol::TYPE::X)
  enum_<Symbol::TYPE>(sym, "TYPE")
    ENTRY(NOTYPE)
    ENTRY(OBJECT)
    ENTRY(FUNC)
    ENTRY(SECTION)
    ENTRY(FILE)
    ENTRY(COMMON)
    ENTRY(TLS)
    ENTRY(GNU_IFUNC)
  ;
  #undef ENTRY

  #define ENTRY(X) .value(to_string(Symbol::VISIBILITY::X), Symbol::VISIBILITY::X)
  enum_<Symbol::VISIBILITY>(sym, "VISIBILITY")
    ENTRY(DEFAULT)
    ENTRY(INTERNAL)
    ENTRY(HIDDEN)
    ENTRY(PROTECTED)
  ;
  #undef ENTRY

  sym
    .def(nb::init<>())
    .def_prop_ro("demangled_name",
        &Symbol::demangled_name,
        "Symbol's name demangled or an empty string if the demangling is not possible/failed"_doc)

    .def_prop_rw("type",
        nb::overload_cast<>(&Symbol::type, nb::const_),
        nb::overload_cast<Symbol::TYPE>(&Symbol::type),
        "The symbol's type provides a general classification for the associated entity."_doc)

    .def_prop_rw("binding",
        nb::overload_cast<>(&Symbol::binding, nb::const_),
        nb::overload_cast<Symbol::BINDING>(&Symbol::binding),
        "A symbol's binding determines the linkage visibility and behavior."_doc)

    .def_prop_rw("information",
        nb::overload_cast<>(&Symbol::information, nb::const_),
        nb::overload_cast<uint8_t>(&Symbol::information),
        "This property specifies the symbol's type and binding attributes"_doc)

    .def_prop_rw("other",
        nb::overload_cast<>(&Symbol::other, nb::const_),
        nb::overload_cast<uint8_t>(&Symbol::other),
        "Alias for " RST_ATTR_REF(lief.ELF.Symbol.visibility) ""_doc)

    .def_prop_rw("visibility",
        nb::overload_cast<>(&Symbol::visibility, nb::const_),
        nb::overload_cast<Symbol::VISIBILITY>(&Symbol::visibility),
        R"delim(
        Symbol visibility. It's basically an alias on :attr:`~.Symbol.other`
        )delim"_doc)

    .def_prop_rw("value", // Even though it is already defined in the base class (Abstract/Symbol)
                           // We keep the definition to provide a dedicated documentation
        nb::overload_cast<>(&Symbol::value, nb::const_),
        nb::overload_cast<uint64_t>(&Symbol::value),
        R"delim(
        This member has different menaing depending on the symbol's type and the type of the ELF file (library, object, ...)

        - In relocatable files, this property contains the alignment constraints
          of the symbol for which the section index is `SHN_COMMON`.
        - In relocatable files, can also contain a section's offset for a defined symbol.
          That is, `value` is an offset from the beginning of the section associated with this symbol.
        - In executable and libraries, this property contains a virtual address.
        )delim"_doc)

    .def_prop_rw("size",
        nb::overload_cast<>(&Symbol::size, nb::const_),
        nb::overload_cast<uint64_t>(&Symbol::size),
        "Many symbols have associated sizes. For example, a data object's size is the number of "
        "bytes contained in the object. This member holds `0` if the symbol has no size or "
        "an unknown size."_doc)

    .def_prop_rw("shndx",
        nb::overload_cast<>(&Symbol::shndx, nb::const_),
        nb::overload_cast<uint16_t>(&Symbol::shndx),
        "Section index associated with the symbol"_doc)

    .def_prop_ro("has_version",
        &Symbol::has_version,
        "Check if this symbols has a " RST_CLASS_REF(lief.ELF.SymbolVersion) ""_doc)

    .def_prop_ro("symbol_version",
        nb::overload_cast<>(&Symbol::symbol_version),
        R"delim(
        Return the :class:`~lief.ELF.SymbolVersion` associated with this symbol

        It returns None if no version is tied to this symbol.
        )delim"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("section",
        nb::overload_cast<>(&Symbol::section),
        R"delim(
        Return the section (:class:`~lief.ELF.Section`) associated with this symbol
        if any. Otherwise, return None.
        )delim"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("is_static",
        &Symbol::is_static,
        "True if the symbol is a static visibility"_doc)

    .def_prop_ro("is_function",
        &Symbol::is_function,
        "True if the symbol is a function"_doc)

    .def_prop_ro("is_variable",
        &Symbol::is_variable,
        "True if the symbol is a variable"_doc)

    .def_prop_rw("exported",
        &Symbol::is_exported, &Symbol::set_exported,
        "Whether the symbol is **exported**"_doc)

    .def_prop_rw("imported",
        &Symbol::is_imported, &Symbol::set_imported,
        "Whether the symbol is **imported**"_doc)

    LIEF_DEFAULT_STR(Symbol);
}

}
