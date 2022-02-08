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
#include "LIEF/PE/Header.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (Header::*)(void) const;

template<class T>
using setter_t = void (Header::*)(T);


template<>
void create<Header>(py::module& m) {
  py::class_<Header, LIEF::Object>(m, "Header",
      R"delim(
      Class that represents the PE header (which follows the :class:`lief.PE.DosHeader`)
      )delim")
    .def(py::init<>())

    .def_property("signature",
        static_cast<getter_t<const Header::signature_t&>>(&Header::signature),
        static_cast<setter_t<const Header::signature_t&>>(&Header::signature),
        "Signature (or magic byte) of the header. It must be: ``PE\\0\\0``")

    .def_property("machine",
        static_cast<getter_t<MACHINE_TYPES>>(&Header::machine),
        static_cast<setter_t<MACHINE_TYPES>>(&Header::machine),
        "The target machine architecture: " RST_CLASS_REF(lief.PE.MACHINE_TYPES) "")

    .def_property("numberof_sections",
        static_cast<getter_t<uint16_t>>(&Header::numberof_sections),
        static_cast<setter_t<uint16_t>>(&Header::numberof_sections),
        "Number of sections in the binary")

    .def_property("time_date_stamps",
        static_cast<getter_t<uint32_t>>(&Header::time_date_stamp),
        static_cast<setter_t<uint32_t>>(&Header::time_date_stamp),
        "The low 32 bits of the number of seconds since 00:00 January 1, 1970 that indicates when the file was created.")

    .def_property("pointerto_symbol_table",
        static_cast<getter_t<uint32_t>>(&Header::pointerto_symbol_table),
        static_cast<setter_t<uint32_t>>(&Header::pointerto_symbol_table),
        R"delim(
        The file offset of the COFF symbol table, or zero if no COFF symbol table is present.

        This value should be zero for an image because COFF debugging information is deprecated.
        )delim")

    .def_property("numberof_symbols",
        static_cast<getter_t<uint32_t>>(&Header::numberof_symbols),
        static_cast<setter_t<uint32_t>>(&Header::numberof_symbols),
        R"delim(
        The number of entries in the symbol table. This data can be used to locate the string table
        which immediately follows the symbol table.

        This value should be zero for an image because COFF debugging information is deprecated.
        )delim")

    .def_property("sizeof_optional_header",
        static_cast<getter_t<uint16_t>>(&Header::sizeof_optional_header),
        static_cast<setter_t<uint16_t>>(&Header::sizeof_optional_header),
        R"delim(
        Size of the :class:`~lief.PE.OptionalHeader` **AND** the data directories which follows this header.

        This value is equivalent to: ``sizeof(pe_optional_header) + NB_DATA_DIR * sizeof(data_directory)``

        This size **should** be either:

          * 0xE0 (224) for a PE32  (32 bits)
          * 0xF0 (240) for a PE32+ (64 bits)
        )delim")

    .def_property("characteristics",
        static_cast<getter_t<HEADER_CHARACTERISTICS>>(&Header::characteristics),
        static_cast<getter_t<HEADER_CHARACTERISTICS>>(&Header::characteristics),
        "The " RST_CLASS_REF(lief.PE.HEADER_CHARACTERISTICS) " that indicate the attributes of the file.")

    .def("has_characteristic",
        &Header::has_characteristic,
        "``True`` if the header has the given " RST_CLASS_REF(lief.PE.HEADER_CHARACTERISTICS) "",
        "characteristic"_a)

    .def("add_characteristic",
        &Header::add_characteristic,
        "Add the given " RST_CLASS_REF(lief.PE.HEADER_CHARACTERISTICS) " to the header",
        "characteristic"_a)

    .def("remove_characteristic",
        &Header::remove_characteristic,
        "Remove the given " RST_CLASS_REF(lief.PE.HEADER_CHARACTERISTICS) " from the header",
        "characteristic"_a)

    .def_property_readonly("characteristics_list",
        &Header::characteristics_list,
        "Return the " RST_CLASS_REF(lief.PE.HEADER_CHARACTERISTICS) " as a ``list``")


    .def("__eq__", &Header::operator==)
    .def("__ne__", &Header::operator!=)
    .def("__hash__",
        [] (const Header& header) {
          return Hash::hash(header);
        })


    .def("__str__", [] (const Header& header)
        {
          std::ostringstream stream;
          stream << header;
          std::string str = stream.str();
          return str;
        });
}
}
}
