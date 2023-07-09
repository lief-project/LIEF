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
#include <string>
#include <sstream>

#include <nanobind/stl/string.h>
#include <nanobind/stl/set.h>
#include <nanobind/stl/array.h>

#include "ELF/pyELF.hpp"

#include "LIEF/ELF/Header.hpp"

namespace LIEF::ELF::py {

template<>
void create<Header>(nb::module_& m) {

  nb::class_<Header, LIEF::Object>(m, "Header",
      R"delim(
      Class which represents the ELF's header. This is the ELF structure
      that starts an ELF file.
      )delim"_doc)
    .def(nb::init<>())

    .def_prop_rw("identity_class",
        nb::overload_cast<>(&Header::identity_class, nb::const_),
        nb::overload_cast<ELF_CLASS>(&Header::identity_class),
        "Header's " RST_CLASS_REF(lief.ELF.ELF_CLASS) "."_doc)

    .def_prop_rw("identity_data",
        nb::overload_cast<>(&Header::identity_data, nb::const_),
        nb::overload_cast<ELF_DATA>(&Header::identity_data),
        "Specify the data encoding (" RST_CLASS_REF(lief.ELF.ELF_DATA) ")"_doc)

    .def_prop_rw("identity_version",
        nb::overload_cast<>(&Header::identity_version, nb::const_),
        nb::overload_cast<VERSION>(&Header::identity_version),
        "Return header's " RST_CLASS_REF(lief.ELF.VERSION) "."_doc)

    .def_prop_rw("identity_os_abi",
        nb::overload_cast<>(&Header::identity_os_abi, nb::const_),
        nb::overload_cast<OS_ABI>(&Header::identity_os_abi),
        "Identifies the version of the ABI for which the object is prepared (" RST_CLASS_REF(lief.ELF.OS_ABI) ")."_doc)

    .def_prop_rw("identity_abi_version",
        nb::overload_cast<>(&Header::identity_abi_version, nb::const_),
        nb::overload_cast<uint32_t>(&Header::identity_abi_version),
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
        nb::overload_cast<E_TYPE>(&Header::file_type),
        "Return binary's " RST_CLASS_REF(lief.ELF.E_TYPE) ". This field determines if the binary \
        is a executable, a library..."_doc)

    .def_prop_rw("machine_type",
        nb::overload_cast<>(&Header::machine_type, nb::const_),
        nb::overload_cast<ARCH>(&Header::machine_type),
        "Return the target architecture (" RST_CLASS_REF(lief.ELF.ARCH) ")"_doc)

    .def_prop_rw("object_file_version",
        nb::overload_cast<>(&Header::object_file_version, nb::const_),
        nb::overload_cast<VERSION>(&Header::object_file_version),
        "Return the " RST_CLASS_REF(lief.ELF.VERSION) ""_doc)

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

    .def_prop_ro("arm_flags_list",
        &Header::arm_flags_list,
        "Return a list of " RST_CLASS_REF(lief.ELF.ARM_EFLAGS) " present in "
        ":attr:`~lief.ELF.Header.processor_flag`"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("mips_flags_list",
        &Header::mips_flags_list,
        "Return a list of " RST_CLASS_REF(lief.ELF.MIPS_EFLAGS) " present in "
        ":attr:`~lief.ELF.Header.processor_flag`"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("ppc64_flags_list",
        &Header::ppc64_flags_list,
        "Return a list of " RST_CLASS_REF(lief.ELF.PPC64_EFLAGS) " present in "
        ":attr:`~lief.ELF.Header.processor_flag`"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("hexagon_flags_list",
        &Header::hexagon_flags_list,
        "Return a list of " RST_CLASS_REF(lief.ELF.HEXAGON_EFLAGS) " present in "
        ":attr:`~lief.ELF.Header.processor_flag`"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("loongarch_flags_list",
        &Header::loongarch_flags_list,
        "Return a list of " RST_CLASS_REF(lief.ELF.LOONGARCH_EFLAGS) " present in "
        ":attr:`~lief.ELF.Header.processor_flag`"_doc,
        nb::rv_policy::reference_internal)

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
        Return the size of a Segment header (:class:`lief.ELF.Segment`)

        This size should be 56 for a ``ELF64`` binary and 32 for an ``ELF32``.
        )delim"_doc)

    .def_prop_rw("numberof_segments",
        nb::overload_cast<>(&Header::numberof_segments, nb::const_),
        nb::overload_cast<uint32_t>(&Header::numberof_segments),
        "Return the number of program headers (segments)"_doc)

    .def_prop_rw("section_header_size",
        nb::overload_cast<>(&Header::section_header_size, nb::const_),
        nb::overload_cast<uint32_t>(&Header::section_header_size),
        R"delim(
        Return the size of a Section header (:class:`lief.ELF.Section`)

        This size should be 64 for a ``ELF64`` binary and 40 for an ``ELF32``.
        )delim"_doc)

    .def_prop_rw("numberof_sections",
        nb::overload_cast<>(&Header::numberof_sections, nb::const_),
        nb::overload_cast<uint32_t>(&Header::numberof_sections),
        "Return the number of sections"_doc)

    .def_prop_rw("section_name_table_idx",
        nb::overload_cast<>(&Header::section_name_table_idx, nb::const_),
        nb::overload_cast<uint32_t>(&Header::section_name_table_idx),
        "Return the section index which contains sections' names"_doc)

    .def("__contains__",
        nb::overload_cast<ARM_EFLAGS>(&Header::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.ELF.ARM_EFLAGS) " is present in "
        ":attr:`~lief.ELF.Header.processor_flag`"_doc)


    .def("__contains__",
        nb::overload_cast<MIPS_EFLAGS>(&Header::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.ELF.MIPS_EFLAGS) " is present in "
        ":attr:`~lief.ELF.Header.processor_flag`"_doc)


    .def("__contains__",
        nb::overload_cast<PPC64_EFLAGS>(&Header::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.ELF.PPC64_EFLAGS) " is present in "
        ":attr:`~lief.ELF.Header.processor_flag`"_doc)


    .def("__contains__",
        nb::overload_cast<HEXAGON_EFLAGS>(&Header::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.ELF.HEXAGON_EFLAGS) " is present in "
        ":attr:`~lief.ELF.Header.processor_flag`"_doc)

    .def("__contains__",
        nb::overload_cast<LOONGARCH_EFLAGS>(&Header::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.ELF.LOONGARCH_EFLAGS) " is present in "
        ":attr:`~lief.ELF.Header.processor_flag`"_doc)

    LIEF_DEFAULT_STR(LIEF::ELF::Header);
}

}
