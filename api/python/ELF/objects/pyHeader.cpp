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
#include <string>
#include <sstream>

#include "pyELF.hpp"

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/Header.hpp"

namespace LIEF {
namespace ELF {

template<class T>
using getter_t = T (Header::*)(void) const;

template<class T>
using setter_t = void (Header::*)(T);


template<>
void create<Header>(py::module& m) {

  py::class_<Header, LIEF::Object>(m, "Header",
      R"delim(
      Class which represents the ELF's header. This is the ELF structure
      that starts an ELF file.
      )delim")
    .def(py::init<>())

    .def_property("identity_class",
        static_cast<getter_t<ELF_CLASS>>(&Header::identity_class),
        static_cast<setter_t<ELF_CLASS>>(&Header::identity_class),
        "Header's " RST_CLASS_REF(lief.ELF.ELF_CLASS) "."
        )

    .def_property("identity_data",
        static_cast<getter_t<ELF_DATA>>(&Header::identity_data),
        static_cast<setter_t<ELF_DATA>>(&Header::identity_data),
        "Specify the data encoding: " RST_CLASS_REF(lief.ELF.ELF_DATA) "."
        )

    .def_property("identity_version",
        static_cast<getter_t<VERSION>>(&Header::identity_version),
        static_cast<setter_t<VERSION>>(&Header::identity_version),
        "Return header's " RST_CLASS_REF(lief.ELF.VERSION) "."
        )

    .def_property("identity_os_abi",
        static_cast<getter_t<OS_ABI>>(&Header::identity_os_abi),
        static_cast<setter_t<OS_ABI>>(&Header::identity_os_abi),
        "Identifies the version of the ABI for which the object is prepared (" RST_CLASS_REF(lief.ELF.OS_ABI) ")."
        )

    .def_property("identity_abi_version",
        static_cast<getter_t<uint32_t>>(&Header::identity_abi_version),
        static_cast<setter_t<uint32_t>>(&Header::identity_abi_version),
        "Return the ABI version (integer)."
        )

    .def_property("identity",
        static_cast<Header::identity_t& (Header::*)(void)>(&Header::identity),
        [] (Header& header, const py::object& obj) {
          if (py::isinstance<py::str>(obj)) {
            header.identity(obj.cast<std::string>());
            return;
          }

          if (py::isinstance<py::bytes>(obj)) {
            header.identity(obj.cast<Header::identity_t>());
            return;
          }

          if (py::isinstance<py::list>(obj)) {
            header.identity(obj.cast<Header::identity_t>());
            return;
          }

          std::string error_str = py::repr(obj).cast<std::string>();
          error_str = error_str + " is not supported!";
          throw py::type_error(error_str.c_str());
        },
        "Header's identity.",
        py::return_value_policy::reference_internal
      )

    .def_property("file_type",
        static_cast<getter_t<E_TYPE>>(&Header::file_type),
        static_cast<setter_t<E_TYPE>>(&Header::file_type),
        "Return binary's " RST_CLASS_REF(lief.ELF.E_TYPE) ". This field determines if the binary \
        is a executable, a library..."
        )

    .def_property("machine_type",
        static_cast<getter_t<ARCH>>(&Header::machine_type),
        static_cast<setter_t<ARCH>>(&Header::machine_type),
        "Return the target architecture (" RST_CLASS_REF(lief.ELF.ARCH) ")")

    .def_property("object_file_version",
        static_cast<getter_t<VERSION>>(&Header::object_file_version),
        static_cast<setter_t<VERSION>>(&Header::object_file_version),
        "Return the " RST_CLASS_REF(lief.ELF.VERSION) "")

    .def_property("entrypoint",
        static_cast<getter_t<uint64_t>>(&Header::entrypoint),
        static_cast<setter_t<uint64_t>>(&Header::entrypoint),
        "Return the binary entry point")

    .def_property("program_header_offset",
        static_cast<getter_t<uint64_t>>(&Header::program_headers_offset),
        static_cast<setter_t<uint64_t>>(&Header::program_headers_offset),
        "Offset of program table (also known as segments table)")

    .def_property("section_header_offset",
        static_cast<getter_t<uint64_t>>(&Header::section_headers_offset),
        static_cast<setter_t<uint64_t>>(&Header::section_headers_offset),
        "Offset of section table")

    .def_property("processor_flag",
        static_cast<getter_t<uint32_t>>(&Header::processor_flag),
        static_cast<setter_t<uint32_t>>(&Header::processor_flag),
        "Processor-specific flags")

    .def_property_readonly("arm_flags_list",
        &Header::arm_flags_list,
        "Return a list of " RST_CLASS_REF(lief.ELF.ARM_EFLAGS) " present in "
        ":attr:`~lief.ELF.Header.processor_flag`",
        py::return_value_policy::reference_internal)

    .def_property_readonly("mips_flags_list",
        &Header::mips_flags_list,
        "Return a list of " RST_CLASS_REF(lief.ELF.MIPS_EFLAGS) " present in "
        ":attr:`~lief.ELF.Header.processor_flag`",
        py::return_value_policy::reference_internal)

    .def_property_readonly("ppc64_flags_list",
        &Header::ppc64_flags_list,
        "Return a list of " RST_CLASS_REF(lief.ELF.PPC64_EFLAGS) " present in "
        ":attr:`~lief.ELF.Header.processor_flag`",
        py::return_value_policy::reference_internal)

    .def_property_readonly("hexagon_flags_list",
        &Header::hexagon_flags_list,
        "Return a list of " RST_CLASS_REF(lief.ELF.HEXAGON_EFLAGS) " present in "
        ":attr:`~lief.ELF.Header.processor_flag`",
        py::return_value_policy::reference_internal)

    .def_property("header_size",
        static_cast<getter_t<uint32_t>>(&Header::header_size),
        static_cast<setter_t<uint32_t>>(&Header::header_size),
        R"delim(
        Return the size of the ELF header

        This size should be 64 for an ``ELF64`` binary and 52 for an ``ELF32``.
        )delim")

    .def_property("program_header_size",
        static_cast<getter_t<uint32_t>>(&Header::program_header_size),
        static_cast<setter_t<uint32_t>>(&Header::program_header_size),
        R"delim(
        Return the size of a Segment header (:class:`lief.ELF.Segment`)

        This size should be 56 for a ``ELF64`` binary and 32 for an ``ELF32``.
        )delim")

    .def_property("numberof_segments",
        static_cast<getter_t<uint32_t>>(&Header::numberof_segments),
        static_cast<setter_t<uint32_t>>(&Header::numberof_segments),
        "Return the number of program headers (segments)")

    .def_property("section_header_size",
        static_cast<getter_t<uint32_t>>(&Header::section_header_size),
        static_cast<setter_t<uint32_t>>(&Header::section_header_size),
        R"delim(
        Return the size of a Section header (:class:`lief.ELF.Section`)

        This size should be 64 for a ``ELF64`` binary and 40 for an ``ELF32``.
        )delim")

    .def_property("numberof_sections",
        static_cast<getter_t<uint32_t>>(&Header::numberof_sections),
        static_cast<setter_t<uint32_t>>(&Header::numberof_sections),
        "Return the number of sections")

    .def_property("section_name_table_idx",
        static_cast<getter_t<uint32_t>>(&Header::section_name_table_idx),
        static_cast<setter_t<uint32_t>>(&Header::section_name_table_idx),
        "Return the section index which contains sections' names")

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

}
}
