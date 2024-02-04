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
#include "enums_wrapper.hpp"

#include "LIEF/PE/Header.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/array.h>
#include <nanobind/stl/vector.h>

#define PY_ENUM(x) to_string(x), x

namespace LIEF::PE::py {

template<>
void create<Header>(nb::module_& m) {
  nb::class_<Header, Object> hdr(m, "Header",
      R"delim(
      Class that represents the PE header (which follows the :class:`lief.PE.DosHeader`)
      )delim"_doc);

  enum_<Header::MACHINE_TYPES>(hdr, "MACHINE_TYPES")
    .value(PY_ENUM(Header::MACHINE_TYPES::UNKNOWN))
    .value(PY_ENUM(Header::MACHINE_TYPES::AM33))
    .value(PY_ENUM(Header::MACHINE_TYPES::AMD64))
    .value(PY_ENUM(Header::MACHINE_TYPES::ARM))
    .value(PY_ENUM(Header::MACHINE_TYPES::ARMNT))
    .value(PY_ENUM(Header::MACHINE_TYPES::ARM64))
    .value(PY_ENUM(Header::MACHINE_TYPES::EBC))
    .value(PY_ENUM(Header::MACHINE_TYPES::I386))
    .value(PY_ENUM(Header::MACHINE_TYPES::IA64))
    .value(PY_ENUM(Header::MACHINE_TYPES::M32R))
    .value(PY_ENUM(Header::MACHINE_TYPES::MIPS16))
    .value(PY_ENUM(Header::MACHINE_TYPES::MIPSFPU))
    .value(PY_ENUM(Header::MACHINE_TYPES::MIPSFPU16))
    .value(PY_ENUM(Header::MACHINE_TYPES::POWERPC))
    .value(PY_ENUM(Header::MACHINE_TYPES::POWERPCFP))
    .value(PY_ENUM(Header::MACHINE_TYPES::R4000))
    .value(PY_ENUM(Header::MACHINE_TYPES::SH3))
    .value(PY_ENUM(Header::MACHINE_TYPES::SH3DSP))
    .value(PY_ENUM(Header::MACHINE_TYPES::SH4))
    .value(PY_ENUM(Header::MACHINE_TYPES::SH5))
    .value(PY_ENUM(Header::MACHINE_TYPES::THUMB))
    .value(PY_ENUM(Header::MACHINE_TYPES::WCEMIPSV2));

  enum_<Header::CHARACTERISTICS>(hdr, "CHARACTERISTICS", nb::is_arithmetic())
    .value(PY_ENUM(Header::CHARACTERISTICS::RELOCS_STRIPPED))
    .value(PY_ENUM(Header::CHARACTERISTICS::EXECUTABLE_IMAGE))
    .value(PY_ENUM(Header::CHARACTERISTICS::LINE_NUMS_STRIPPED))
    .value(PY_ENUM(Header::CHARACTERISTICS::LOCAL_SYMS_STRIPPED))
    .value(PY_ENUM(Header::CHARACTERISTICS::AGGRESSIVE_WS_TRIM))
    .value(PY_ENUM(Header::CHARACTERISTICS::LARGE_ADDRESS_AWARE))
    .value(PY_ENUM(Header::CHARACTERISTICS::BYTES_REVERSED_LO))
    .value(PY_ENUM(Header::CHARACTERISTICS::NEED_32BIT_MACHINE))
    .value(PY_ENUM(Header::CHARACTERISTICS::DEBUG_STRIPPED))
    .value(PY_ENUM(Header::CHARACTERISTICS::REMOVABLE_RUN_FROM_SWAP))
    .value(PY_ENUM(Header::CHARACTERISTICS::NET_RUN_FROM_SWAP))
    .value(PY_ENUM(Header::CHARACTERISTICS::SYSTEM))
    .value(PY_ENUM(Header::CHARACTERISTICS::DLL))
    .value(PY_ENUM(Header::CHARACTERISTICS::UP_SYSTEM_ONLY))
    .value(PY_ENUM(Header::CHARACTERISTICS::BYTES_REVERSED_HI));

  hdr
    .def_static("create", &Header::create, "type"_a)

    .def_prop_rw("signature",
        nb::overload_cast<>(&Header::signature, nb::const_),
        nb::overload_cast<const Header::signature_t&>(&Header::signature),
        R"delim(
        Signature (or magic byte) of the header. It must be: ``PE\0\0``
        )delim"_doc)

    .def_prop_rw("machine",
        nb::overload_cast<>(&Header::machine, nb::const_),
        nb::overload_cast<Header::MACHINE_TYPES>(&Header::machine),
        "The target machine architecture (" RST_CLASS_REF(lief.PE.Header.MACHINE_TYPES) ")"_doc)

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
        "The " RST_CLASS_REF(lief.PE.Header.CHARACTERISTICS) " that indicate the attributes of the file."_doc)

    .def("has_characteristic",
        &Header::has_characteristic,
        "``True`` if the header has the given " RST_CLASS_REF(lief.PE.Header.CHARACTERISTICS) ""_doc,
        "characteristic"_a)

    .def("add_characteristic",
        &Header::add_characteristic,
        "Add the given " RST_CLASS_REF(lief.PE.Header.CHARACTERISTICS) " to the header"_doc,
        "characteristic"_a)

    .def("remove_characteristic",
        &Header::remove_characteristic,
        "Remove the given " RST_CLASS_REF(lief.PE.Header.CHARACTERISTICS) " from the header"_doc,
        "characteristic"_a)

    .def_prop_ro("characteristics_list",
        &Header::characteristics_list,
        "Return the " RST_CLASS_REF(lief.PE.Header.CHARACTERISTICS) " as a ``list``"_doc)

    LIEF_COPYABLE(Header)
    LIEF_DEFAULT_STR(Header);
}
}
