/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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

#include "pyELF.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/Header.hpp"

template<class T>
using getter_t = T (Header::*)(void) const;

template<class T>
using setter_t = void (Header::*)(T);

void init_ELF_Header_class(py::module& m) {

  //
  // Header object
  //
  py::class_<Header, LIEF::Object>(m, "Header")
    .def(py::init<>())

    .def_property("identity_class",
        static_cast<getter_t<ELF_CLASS>>(&Header::identity_class),
        static_cast<setter_t<ELF_CLASS>>(&Header::identity_class),
        "Return header's " RST_CLASS_REF(lief.ELF.ELF_CLASS) "."
        )

    .def_property("identity_data",
        static_cast<getter_t<ELF_DATA>>(&Header::identity_data),
        static_cast<setter_t<ELF_DATA>>(&Header::identity_data),
        "Return header's " RST_CLASS_REF(lief.ELF.ELF_DATA) "."
        )

    .def_property("identity_version",
        static_cast<getter_t<VERSION>>(&Header::identity_version),
        static_cast<setter_t<VERSION>>(&Header::identity_version),
        "Return header's " RST_CLASS_REF(lief.ELF.VERSION) "."
        )

    .def_property("identity_os_abi",
        static_cast<getter_t<OS_ABI>>(&Header::identity_os_abi),
        static_cast<setter_t<OS_ABI>>(&Header::identity_os_abi),
        "Return header's " RST_CLASS_REF(lief.ELF.OS_ABI) "."
        )

    .def_property_readonly("identity",
        static_cast<Header::identity_t& (Header::*)(void)>(&Header::identity),
        "Return header's identity.",
        py::return_value_policy::reference_internal
        )

    .def_property("file_type",
        static_cast<getter_t<E_TYPE>>(&Header::file_type),
        static_cast<setter_t<E_TYPE>>(&Header::file_type),
        "Return binary's " RST_CLASS_REF(lief.ELF.E_TYPE) ". It determine if the binary \
        is a executable, a library..."
        )

    .def_property("machine_type",
        static_cast<getter_t<ARCH>>(&Header::machine_type),
        static_cast<setter_t<ARCH>>(&Header::machine_type),
        "Return target architecture (" RST_CLASS_REF(lief.ELF.ARCH) ")")

    .def_property("object_file_version",
        static_cast<getter_t<VERSION>>(&Header::object_file_version),
        static_cast<setter_t<VERSION>>(&Header::object_file_version),
        "Return " RST_CLASS_REF(lief.ELF.VERSION) "")

    .def_property("entrypoint",
        static_cast<getter_t<uint64_t>>(&Header::entrypoint),
        static_cast<setter_t<uint64_t>>(&Header::entrypoint),
        "Return binary entry point")

    .def_property("program_header_offset",
        static_cast<getter_t<uint64_t>>(&Header::program_headers_offset),
        static_cast<setter_t<uint64_t>>(&Header::program_headers_offset),
        "Return file offset to the program header table")

    .def_property("section_header_offset",
        static_cast<getter_t<uint64_t>>(&Header::section_headers_offset),
        static_cast<setter_t<uint64_t>>(&Header::section_headers_offset),
        "Return file offset to the section header table")

    .def_property("processor_flag",
        static_cast<getter_t<uint32_t>>(&Header::processor_flag),
        static_cast<setter_t<uint32_t>>(&Header::processor_flag))

    .def_property_readonly("arm_flags_list",
        &Header::arm_flags_list,
        "Return list of " RST_CLASS_REF(lief.ELF.ARM_EFLAGS) " present in "
        ":attr:`~lief.ELF.Header.processor_flag`",
        py::return_value_policy::reference_internal)

    .def_property_readonly("mips_flags_list",
        &Header::mips_flags_list,
        "Return list of " RST_CLASS_REF(lief.ELF.MIPS_EFLAGS) " present in "
        ":attr:`~lief.ELF.Header.processor_flag`",
        py::return_value_policy::reference_internal)

    .def_property_readonly("ppc64_flags_list",
        &Header::ppc64_flags_list,
        "Return list of " RST_CLASS_REF(lief.ELF.PPC64_EFLAGS) " present in "
        ":attr:`~lief.ELF.Header.processor_flag`",
        py::return_value_policy::reference_internal)

    .def_property_readonly("hexagon_flags_list",
        &Header::hexagon_flags_list,
        "Return list of " RST_CLASS_REF(lief.ELF.HEXAGON_EFLAGS) " present in "
        ":attr:`~lief.ELF.Header.processor_flag`",
        py::return_value_policy::reference_internal)

    .def_property("header_size",
        static_cast<getter_t<uint32_t>>(&Header::header_size),
        static_cast<setter_t<uint32_t>>(&Header::header_size),
        "Return the size of the ELF header")

    .def_property("program_header_size",
        static_cast<getter_t<uint32_t>>(&Header::program_header_size),
        static_cast<setter_t<uint32_t>>(&Header::program_header_size),
        "Return this size of a program header entry")

    .def_property("numberof_segments",
        static_cast<getter_t<uint32_t>>(&Header::numberof_segments),
        static_cast<setter_t<uint32_t>>(&Header::numberof_segments),
        "Return the number of program headers (segments)")

    .def_property("section_header_size",
        static_cast<getter_t<uint32_t>>(&Header::section_header_size),
        static_cast<setter_t<uint32_t>>(&Header::section_header_size),
        "Return the size of a section header entry")

    .def_property("numberof_sections",
        static_cast<getter_t<uint32_t>>(&Header::numberof_sections),
        static_cast<setter_t<uint32_t>>(&Header::numberof_sections),
        "Return the number of section's headers")

    .def_property("section_name_table_idx",
        static_cast<getter_t<uint32_t>>(&Header::section_name_table_idx),
        static_cast<setter_t<uint32_t>>(&Header::section_name_table_idx),
        "Return the section index which hold sections's name")

    .def("__eq__", &Header::operator==)
    .def("__ne__", &Header::operator!=)
    .def("__hash__",
        [] (const Header& header) {
          return Hash::hash(header);
        })

    .def("__contains__",
        static_cast<bool (Header::*)(ARM_EFLAGS) const>(&Header::has),
        "Check if the given " RST_CLASS_REF(lief.ELF.ARM_EFLAGS) " is present in "
        ":attr:`~lief.ELF.Header.processor_flag`")


    .def("__contains__",
        static_cast<bool (Header::*)(MIPS_EFLAGS) const>(&Header::has),
        "Check if the given " RST_CLASS_REF(lief.ELF.MIPS_EFLAGS) " is present in "
        ":attr:`~lief.ELF.Header.processor_flag`")


    .def("__contains__",
        static_cast<bool (Header::*)(PPC64_EFLAGS) const>(&Header::has),
        "Check if the given " RST_CLASS_REF(lief.ELF.PPC64_EFLAGS) " is present in "
        ":attr:`~lief.ELF.Header.processor_flag`")


    .def("__contains__",
        static_cast<bool (Header::*)(HEXAGON_EFLAGS) const>(&Header::has),
        "Check if the given " RST_CLASS_REF(lief.ELF.HEXAGON_EFLAGS) " is present in "
        ":attr:`~lief.ELF.Header.processor_flag`")

    .def("__str__",
        [] (const Header& header)
        {
          std::ostringstream stream;
          stream << header;
          std::string str =  stream.str();
          return str;
        });
}
