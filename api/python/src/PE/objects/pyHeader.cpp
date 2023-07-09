/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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

#include "LIEF/PE/Header.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/array.h>
#include <nanobind/stl/set.h>

namespace LIEF::PE::py {

template<>
void create<Header>(nb::module_& m) {
  nb::class_<Header, LIEF::Object>(m, "Header",
      R"delim(
      Class that represents the PE header (which follows the :class:`lief.PE.DosHeader`)
      )delim"_doc)
    .def(nb::init<>())

    .def_prop_rw("signature",
        nb::overload_cast<>(&Header::signature, nb::const_),
        nb::overload_cast<const Header::signature_t&>(&Header::signature),
        R"delim(
        Signature (or magic byte) of the header. It must be: ``PE\0\0``
        )delim"_doc)

    .def_prop_rw("machine",
        nb::overload_cast<>(&Header::machine, nb::const_),
        nb::overload_cast<MACHINE_TYPES>(&Header::machine),
        "The target machine architecture (" RST_CLASS_REF(lief.PE.MACHINE_TYPES) ")"_doc)

    .def_prop_rw("numberof_sections",
        nb::overload_cast<>(&Header::numberof_sections, nb::const_),
        nb::overload_cast<uint16_t>(&Header::numberof_sections),
        "Number of sections in the binary"_doc)

    .def_prop_rw("time_date_stamps",
        nb::overload_cast<>(&Header::time_date_stamp, nb::const_),
        nb::overload_cast<uint32_t>(&Header::time_date_stamp),
        "The low 32 bits of the number of seconds since 00:00 January 1, 1970 that indicates when the file was created."_doc)

    .def_prop_rw("pointerto_symbol_table",
        nb::overload_cast<>(&Header::pointerto_symbol_table, nb::const_),
        nb::overload_cast<uint32_t>(&Header::pointerto_symbol_table),
        R"delim(
        The file offset of the COFF symbol table, or zero if no COFF symbol table is present.

        This value should be zero for an image because COFF debugging information is deprecated.
        )delim"_doc)

    .def_prop_rw("numberof_symbols",
        nb::overload_cast<>(&Header::numberof_symbols, nb::const_),
        nb::overload_cast<uint32_t>(&Header::numberof_symbols),
        R"delim(
        The number of entries in the symbol table. This data can be used to locate the string table
        which immediately follows the symbol table.

        This value should be zero for an image because COFF debugging information is deprecated.
        )delim"_doc)

    .def_prop_rw("sizeof_optional_header",
        nb::overload_cast<>(&Header::sizeof_optional_header, nb::const_),
        nb::overload_cast<uint16_t>(&Header::sizeof_optional_header),
        R"delim(
        Size of the :class:`~lief.PE.OptionalHeader` **AND** the data directories which follows this header.

        This value is equivalent to: ``sizeof(pe_optional_header) + NB_DATA_DIR * sizeof(data_directory)``

        This size **should** be either:

          * 0xE0 (224) for a PE32  (32 bits)
          * 0xF0 (240) for a PE32+ (64 bits)
        )delim"_doc)

    .def_prop_rw("characteristics",
        nb::overload_cast<>(&Header::characteristics, nb::const_),
        nb::overload_cast<>(&Header::characteristics, nb::const_),
        "The " RST_CLASS_REF(lief.PE.HEADER_CHARACTERISTICS) " that indicate the attributes of the file."_doc)

    .def("has_characteristic",
        &Header::has_characteristic,
        "``True`` if the header has the given " RST_CLASS_REF(lief.PE.HEADER_CHARACTERISTICS) ""_doc,
        "characteristic"_a)

    .def("add_characteristic",
        &Header::add_characteristic,
        "Add the given " RST_CLASS_REF(lief.PE.HEADER_CHARACTERISTICS) " to the header"_doc,
        "characteristic"_a)

    .def("remove_characteristic",
        &Header::remove_characteristic,
        "Remove the given " RST_CLASS_REF(lief.PE.HEADER_CHARACTERISTICS) " from the header"_doc,
        "characteristic"_a)

    .def_prop_ro("characteristics_list",
        &Header::characteristics_list,
        "Return the " RST_CLASS_REF(lief.PE.HEADER_CHARACTERISTICS) " as a ``list``"_doc)

    LIEF_DEFAULT_STR(LIEF::PE::Header);
}
}
