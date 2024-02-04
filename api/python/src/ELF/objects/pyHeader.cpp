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
#include <nanobind/stl/set.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/array.h>

#include "ELF/pyELF.hpp"
#include "enums_wrapper.hpp"

#include "LIEF/ELF/Header.hpp"

namespace LIEF::ELF::py {

template<>
void create<Header>(nb::module_& m) {

  nb::class_<Header, LIEF::Object> header(m, "Header",
      R"delim(
      Class which represents the ELF's header. This class mirrors the raw ELF
      ``Elfxx_Ehdr`` structure.
      )delim"_doc);

  #define ENTRY(X, D) .value(to_string(Header::FILE_TYPE::X), Header::FILE_TYPE::X, D)
  enum_<Header::FILE_TYPE>(header, "FILE_TYPE",
    R"delim(
    The type of the underlying ELF file. This enum matches the semantic of
    ``ET_NONE``, ``ET_REL``, ...
    )delim"_doc
  )
    ENTRY(NONE, "Can't be determined/Invalid"_doc)
    ENTRY(REL, "Relocatable file (or object file)"_doc)
    ENTRY(EXEC, "non-pie executable"_doc)
    ENTRY(DYN, "Shared library **or** a pie-executable"_doc)
    ENTRY(CORE, "Core dump file"_doc)
  ;
  #undef ENTRY

  #define ENTRY(X, D) .value(to_string(Header::VERSION::X), Header::VERSION::X, D)
  enum_<Header::VERSION>(header, "VERSION",
    R"delim(
    Match the result of ``Elfxx_Ehdr.e_version``
    )delim"_doc
  )
    ENTRY(NONE, "Invalid ELF version"_doc)
    ENTRY(CURRENT, "Current version (default)"_doc)
  ;
  #undef ENTRY

  #define ENTRY(X, D) .value(to_string(Header::CLASS::X), Header::CLASS::X, D)
  enum_<Header::CLASS>(header, "CLASS",
    R"delim(
    Match the result of ``Elfxx_Ehdr.e_ident[EI_CLASS]``
    )delim"_doc
  )
    ENTRY(NONE, "Invalid class"_doc)
    ENTRY(ELF32, "32-bit objects"_doc)
    ENTRY(ELF64, "64-bit objects"_doc)
  ;
  #undef ENTRY

  #define ENTRY(X) .value(to_string(Header::OS_ABI::X), Header::OS_ABI::X)
  enum_<Header::OS_ABI>(header, "OS_ABI")
    ENTRY(SYSTEMV)
    ENTRY(HPUX)
    ENTRY(NETBSD)
    ENTRY(GNU)
    ENTRY(LINUX)
    ENTRY(HURD)
    ENTRY(SOLARIS)
    ENTRY(AIX)
    ENTRY(IRIX)
    ENTRY(FREEBSD)
    ENTRY(TRU64)
    ENTRY(MODESTO)
    ENTRY(OPENBSD)
    ENTRY(OPENVMS)
    ENTRY(NSK)
    ENTRY(AROS)
    ENTRY(FENIXOS)
    ENTRY(CLOUDABI)
    ENTRY(C6000_ELFABI)
    ENTRY(AMDGPU_HSA)
    ENTRY(C6000_LINUX)
    ENTRY(ARM)
    ENTRY(STANDALONE)
  ;
  #undef ENTRY

  #define ENTRY(X, D) .value(to_string(Header::ELF_DATA::X), Header::ELF_DATA::X, D)
  enum_<Header::ELF_DATA>(header, "ELF_DATA",
    R"delim(
    Match the result ``Elfxx_Ehdr.e_ident[EI_DATA]``
    )delim"_doc
  )
    ENTRY(NONE, "Invalid data encoding"_doc)
    ENTRY(LSB, "2's complement, little endian"_doc)
    ENTRY(MSB, "2's complement, big endian"_doc)
  ;
  #undef ENTRY

  header
    .def(nb::init<>())

    .def_prop_rw("identity_class",
        nb::overload_cast<>(&Header::identity_class, nb::const_),
        nb::overload_cast<Header::CLASS>(&Header::identity_class),
        "Header's class."_doc)

    .def_prop_rw("identity_data",
        nb::overload_cast<>(&Header::identity_data, nb::const_),
        nb::overload_cast<Header::ELF_DATA>(&Header::identity_data),
        "Specify the data encoding"_doc)

    .def_prop_rw("identity_version",
        nb::overload_cast<>(&Header::identity_version, nb::const_),
        nb::overload_cast<Header::VERSION>(&Header::identity_version))

    .def_prop_rw("identity_os_abi",
        nb::overload_cast<>(&Header::identity_os_abi, nb::const_),
        nb::overload_cast<Header::OS_ABI>(&Header::identity_os_abi),
        "Identifies the version of the ABI for which the object is prepared."_doc)

    .def_prop_rw("identity_abi_version",
        nb::overload_cast<>(&Header::identity_abi_version, nb::const_),
        nb::overload_cast<uint8_t>(&Header::identity_abi_version),
        "Return the ABI version (integer)."_doc)

    .def_prop_rw("identity",
        nb::overload_cast<>(&Header::identity),
        [] (Header& header, const nb::object& obj) {
          if (nb::isinstance<nb::str>(obj)) {
            header.identity(nb::cast<std::string>(obj));
            return;
          }

          if (nb::isinstance<nb::bytes>(obj)) {
            header.identity(nb::cast<Header::identity_t>(obj));
            return;
          }

          if (nb::isinstance<nb::list>(obj)) {
            header.identity(nb::cast<Header::identity_t>(obj));
            return;
          }

          std::string error_str = nb::repr(obj).c_str();
          error_str = error_str + " is not supported!";
          throw nb::type_error(error_str.c_str());
        },
        "Header's identity."_doc,
        nb::rv_policy::reference_internal
      )

    .def_prop_rw("file_type",
        nb::overload_cast<>(&Header::file_type, nb::const_),
        nb::overload_cast<Header::FILE_TYPE>(&Header::file_type),
        "Return binary's type. This field determines if the binary is a "
        "executable, a library..."_doc)

    .def_prop_rw("machine_type",
        nb::overload_cast<>(&Header::machine_type, nb::const_),
        nb::overload_cast<ARCH>(&Header::machine_type),
        "Return the target architecture"_doc)

    .def_prop_rw("object_file_version",
        nb::overload_cast<>(&Header::object_file_version, nb::const_),
        nb::overload_cast<Header::VERSION>(&Header::object_file_version),
        "Return the version"_doc)

    .def_prop_rw("entrypoint",
        nb::overload_cast<>(&Header::entrypoint, nb::const_),
        nb::overload_cast<uint64_t>(&Header::entrypoint),
        "Return the binary entry point"_doc)

    .def_prop_rw("program_header_offset",
        nb::overload_cast<>(&Header::program_headers_offset, nb::const_),
        nb::overload_cast<uint64_t>(&Header::program_headers_offset),
        "Offset of program table (also known as segments table)"_doc)

    .def_prop_rw("section_header_offset",
        nb::overload_cast<>(&Header::section_headers_offset, nb::const_),
        nb::overload_cast<uint64_t>(&Header::section_headers_offset),
        "Offset of section table"_doc)

    .def_prop_rw("processor_flag",
        nb::overload_cast<>(&Header::processor_flag, nb::const_),
        nb::overload_cast<uint32_t>(&Header::processor_flag),
        "Processor-specific flags"_doc)

    .def("has", &Header::has,
        "Check if the given processor flag is present"_doc)

    .def_prop_ro("flags_list", &Header::flags_list,
                 "Processor flags as a list"_doc)

    .def_prop_rw("header_size",
        nb::overload_cast<>(&Header::header_size, nb::const_),
        nb::overload_cast<uint32_t>(&Header::header_size),
        R"delim(
        Return the size of the ELF header
        This size should be 64 for an ``ELF64`` binary and 52 for an ``ELF32``.
        )delim"_doc)

    .def_prop_rw("program_header_size",
        nb::overload_cast<>(&Header::program_header_size, nb::const_),
        nb::overload_cast<uint32_t>(&Header::program_header_size),
        R"delim(
        Return the size of the raw ``Elfxx_Phdr`` structure (see :class:`lief.ELF.Segment`)
        This size should be 56 for an ``ELF64`` binary and 32 for an ``ELF32``.
        )delim"_doc)

    .def_prop_rw("numberof_segments",
        nb::overload_cast<>(&Header::numberof_segments, nb::const_),
        nb::overload_cast<uint32_t>(&Header::numberof_segments),
        "Return the number of program headers (segments)"_doc)

    .def_prop_rw("section_header_size",
        nb::overload_cast<>(&Header::section_header_size, nb::const_),
        nb::overload_cast<uint32_t>(&Header::section_header_size),
        R"delim(
        Return the size of the raw ``Elfxx_Shdr`` (:class:`lief.ELF.Section`)

        This size should be 64 for an ``ELF64`` binary and 40 for an ``ELF32``.
        )delim"_doc)

    .def_prop_rw("numberof_sections",
        nb::overload_cast<>(&Header::numberof_sections, nb::const_),
        nb::overload_cast<uint32_t>(&Header::numberof_sections),
        "Return the number of sections"_doc)

    .def_prop_rw("section_name_table_idx",
        nb::overload_cast<>(&Header::section_name_table_idx, nb::const_),
        nb::overload_cast<uint32_t>(&Header::section_name_table_idx),
        "Return the section index which contains sections' names"_doc)

    LIEF_DEFAULT_STR(Header);
}

}
