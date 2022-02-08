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
#include "pyIterators.hpp"

#include "LIEF/ELF/Symbol.hpp"
#include "LIEF/ELF/SymbolVersion.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/Abstract/Symbol.hpp"


#include <string>
#include <sstream>

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (Symbol::*)(void) const;

template<class T>
using setter_t = void (Symbol::*)(T);


template<>
void create<Symbol>(py::module& m) {

  py::class_<Symbol, LIEF::Symbol>(m, "Symbol",
    R"delim(
    "Class which represents an ELF symbol"
    )delim")
    .def(py::init<>())
    .def_property_readonly("demangled_name",
        &Symbol::demangled_name,
        "Symbol's name demangled or an empty string if the demangling is not possible/failed")

    .def_property("type",
        static_cast<getter_t<ELF_SYMBOL_TYPES>>(&Symbol::type),
        static_cast<setter_t<ELF_SYMBOL_TYPES>>(&Symbol::type),
        "The symbol's type provides a general classification for the associated entity. "
        "See: " RST_CLASS_REF(lief.ELF.SYMBOL_TYPES) "")

    .def_property("binding",
        static_cast<getter_t<SYMBOL_BINDINGS>>(&Symbol::binding),
        static_cast<setter_t<SYMBOL_BINDINGS>>(&Symbol::binding),
        "A symbol's binding determines the linkage visibility and behavior. "
        "See " RST_CLASS_REF(lief.ELF.SYMBOL_BINDINGS) "")

    .def_property("information",
        static_cast<getter_t<uint8_t>>(&Symbol::information),
        static_cast<setter_t<uint8_t>>(&Symbol::information),
        "This property specifies the symbol's type and binding attributes")

    .def_property("other",
        static_cast<getter_t<uint8_t>>(&Symbol::other),
        static_cast<setter_t<uint8_t>>(&Symbol::other),
        "Alias for: " RST_ATTR_REF(lief.ELF.Symbol.visibility) "")

    .def_property("visibility",
        static_cast<getter_t<ELF_SYMBOL_VISIBILITY>>(&Symbol::visibility),
        static_cast<setter_t<ELF_SYMBOL_VISIBILITY>>(&Symbol::visibility),
        R"delim(
        Symbol :class:`~lief.ELF.SYMBOL_VISIBILITY`.
        It's basically an alias on :attr:`~lief.ELF.Symbol.other`
        )delim")

    .def_property("value", // Even though it is already defined in the base class (Abstract/Symbol)
                           // We keep the definition to provide a dedicated documentation
        static_cast<getter_t<uint64_t>>(&Symbol::value),
        static_cast<setter_t<uint64_t>>(&Symbol::value),
        R"delim(
        This member has different menaing depending on the symbol's type and the type of the ELF file (library, object, ...)

        - In relocatable files, this property contains the alignment constraints
          of the symbol for which the section index is `SHN_COMMON`.
        - In relocatable files, can also contain a section's offset for a defined symbol.
          That is, `value` is an offset from the beginning of the section associated with this symbol.
        - In executable and libraries, this property contains a virtual address.
        )delim")

    .def_property("size",
        static_cast<getter_t<uint64_t>>(&Symbol::size),
        static_cast<setter_t<uint64_t>>(&Symbol::size),
        "Many symbols have associated sizes. For example, a data object's size is the number of "
        "bytes contained in the object. This member holds `0` if the symbol has no size or "
        "an unknown size.")

    .def_property("shndx",
        static_cast<getter_t<uint16_t>>(&Symbol::shndx),
        static_cast<setter_t<uint16_t>>(&Symbol::shndx),
        "Section index associated with the symbol")

    .def_property_readonly("has_version",
        &Symbol::has_version,
        "Check if this symbols has a " RST_CLASS_REF(lief.ELF.SymbolVersion) "")

    .def_property_readonly("symbol_version",
        static_cast<SymbolVersion* (Symbol::*)(void)>(&Symbol::symbol_version),
        R"delim(
        Return the :class:`~lief.ELF.SymbolVersion` associated with this symbol

        It returns None if no version is tied to this symbol.
        )delim",
        py::return_value_policy::reference_internal)

    .def_property_readonly("is_static",
        &Symbol::is_static,
        "True if the symbol is a static one (i.e. from the ``.symtab`` section")

    .def_property_readonly("is_function",
        &Symbol::is_function,
        "True if the symbol is a function")

    .def_property_readonly("is_variable",
        &Symbol::is_variable,
        "True if the symbol is a variable")

    .def_property("exported",
        &Symbol::is_exported, &Symbol::set_exported,
        "Whether the symbol is **exported**")

    .def_property("imported",
        &Symbol::is_imported, &Symbol::set_imported,
        "Whether the symbol is **imported**")

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
        return stream.str();
      });
}

}
}
