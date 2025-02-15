/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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
#include "LIEF/PE/COFFString.hpp"
#include "LIEF/PE/Section.hpp"
#include "LIEF/PE/AuxiliarySymbol.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/extra/stl/wstring.h>

#include "enums_wrapper.hpp"
#include "pyIterator.hpp"

namespace LIEF::PE::py {

template<>
void create<Symbol>(nb::module_& m) {
  nb::class_<Symbol, LIEF::Symbol> sym(m, "Symbol",
    R"doc(
    Class that represents a PE-COFF symbol.

    Usually PE debug information (including symbols) are wrapped in a PDB file
    referenced by the :class:`lief.PE.CodeViewPDB` object.

    The PE format allows to define (by COFF inheritance) a symbol table that is
    different from the regular PDB symbols. This table contains COFF(16) symbols
    which can reference auxiliary symbols.

    .. warning::

        The :attr:`lief.Symbol.value` should be interpreted in perspective of
        the :attr:`~.Symbol.storage_class`

    Reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-symbol-table
    )doc"_doc
  );

  LIEF::py::init_ref_iterator<Symbol::it_auxiliary_symbols_t>(sym, "it_auxiliary_symbols_t");

  #define ENTRY(X) .value(to_string(Symbol::STORAGE_CLASS::X), Symbol::STORAGE_CLASS::X)
  enum_<Symbol::STORAGE_CLASS>(sym, "STORAGE_CLASS",
    "Reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#storage-class"_doc
  )
    ENTRY(END_OF_FUNCTION)
    ENTRY(NONE)
    ENTRY(AUTOMATIC)
    ENTRY(EXTERNAL)
    ENTRY(STATIC)
    ENTRY(REGISTER)
    ENTRY(EXTERNAL_DEF)
    ENTRY(LABEL)
    ENTRY(UNDEFINED_LABEL)
    ENTRY(MEMBER_OF_STRUCT)
    ENTRY(ARGUMENT)
    ENTRY(STRUCT_TAG)
    ENTRY(MEMBER_OF_UNION)
    ENTRY(UNION_TAG)
    ENTRY(TYPE_DEFINITION)
    ENTRY(UNDEFINED_STATIC)
    ENTRY(ENUM_TAG)
    ENTRY(MEMBER_OF_ENUM)
    ENTRY(REGISTER_PARAM)
    ENTRY(BIT_FIELD)
    ENTRY(BLOCK)
    ENTRY(FUNCTION)
    ENTRY(END_OF_STRUCT)
    ENTRY(FILE)
    ENTRY(SECTION)
    ENTRY(WEAK_EXTERNAL)
    ENTRY(CLR_TOKEN)
  ;
  #undef ENTRY

  #define ENTRY(X) .value(to_string(Symbol::BASE_TYPE::X), Symbol::BASE_TYPE::X)
  enum_<Symbol::BASE_TYPE>(sym, "BASE_TYPE")
    ENTRY(TY_NULL)
    ENTRY(TY_VOID)
    ENTRY(TY_CHAR)
    ENTRY(TY_SHORT)
    ENTRY(TY_INT)
    ENTRY(TY_LONG)
    ENTRY(TY_FLOAT)
    ENTRY(TY_DOUBLE)
    ENTRY(TY_STRUCT)
    ENTRY(TY_UNION)
    ENTRY(TY_ENUM)
    ENTRY(TY_MOE)
    ENTRY(TY_BYTE)
    ENTRY(TY_WORD)
    ENTRY(TY_UINT)
    ENTRY(TY_DWORD)
  ;
  #undef ENTRY

  #define ENTRY(X) .value(to_string(Symbol::COMPLEX_TYPE::X), Symbol::COMPLEX_TYPE::X)
  enum_<Symbol::COMPLEX_TYPE>(sym, "COMPLEX_TYPE")
    ENTRY(TY_NULL)
    ENTRY(TY_POINTER)
    ENTRY(TY_FUNCTION)
    ENTRY(TY_ARRAY)
  ;
  #undef ENTRY

  sym
    .def_prop_rw("type", nb::overload_cast<>(&Symbol::type, nb::const_),
                 nb::overload_cast<uint16_t>(&Symbol::type),
                 nb::rv_policy::reference,
      R"doc(
      The symbol type. The first byte represents the base type (see: :attr:`~.base_type`)
      while the upper byte represents the complex type, if any (see: :attr:`~.complex_type`).
      )doc"_doc
    )

    .def_prop_ro("base_type", nb::overload_cast<>(&Symbol::base_type, nb::const_),
                 "The simple (base) data type"_doc)

    .def_prop_ro("complex_type", nb::overload_cast<>(&Symbol::complex_type, nb::const_),
                 "The complex type (if any)"_doc)

    .def_prop_ro("storage_class", nb::overload_cast<>(&Symbol::storage_class, nb::const_),
      R"doc(
      Storage class of the symbol which indicates what kind of definition a
      symbol represents.
      )doc"_doc
    )

    .def_prop_rw("section_idx", nb::overload_cast<>(&Symbol::section_idx, nb::const_),
                 nb::overload_cast<int16_t>(&Symbol::section_idx),
                 nb::rv_policy::reference,
      R"doc(
      The signed integer that identifies the section, using a one-based index
      into the section table. Some values have special meaning:

      *  0: The symbol record is not yet assigned a section. A value of zero
            indicates that a reference to an external symbol is defined elsewhere.
            A value of non-zero is a common symbol with a size that is specified
            by the value.
      * -1: The symbol has an absolute (non-relocatable) value and is not an
            address.
      * -2: The symbol provides general type or debugging information but does
            not correspond to a section. Microsoft tools use this setting along
            with ``.file`` records
      )doc"_doc
    )

    .def_prop_ro("is_external", nb::overload_cast<>(&Symbol::is_external, nb::const_))
    .def_prop_ro("is_weak_external", nb::overload_cast<>(&Symbol::is_weak_external, nb::const_))
    .def_prop_ro("is_undefined", nb::overload_cast<>(&Symbol::is_undefined, nb::const_))
    .def_prop_ro("is_function_line_info", nb::overload_cast<>(&Symbol::is_function_line_info, nb::const_))
    .def_prop_ro("is_file_record", nb::overload_cast<>(&Symbol::is_file_record, nb::const_))

    .def_prop_ro("auxiliary_symbols", nb::overload_cast<>(&Symbol::auxiliary_symbols),
                 "Auxiliary symbols associated with this symbol."_doc)

    .def_prop_ro("coff_name", nb::overload_cast<>(&Symbol::coff_name),
                 "COFF string used to represents the (long) symbol name"_doc)


    LIEF_DEFAULT_STR(Symbol);
}

}
