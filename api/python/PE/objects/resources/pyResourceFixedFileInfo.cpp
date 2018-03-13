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
#include "pyPE.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/resources/ResourceFixedFileInfo.hpp"

#include <string>
#include <sstream>


template<class T>
using getter_t = T (ResourceFixedFileInfo::*)(void) const;

template<class T>
using setter_t = void (ResourceFixedFileInfo::*)(T);

void init_PE_ResourceFixedFileInfo_class(py::module& m) {
  py::class_<ResourceFixedFileInfo, LIEF::Object>(m, "ResourceFixedFileInfo",
      "Modelization of the `VS_FIXEDFILEINFO <https://msdn.microsoft.com/en-us/library/windows/desktop/ms646997(v=vs.85).aspx>`_")

    .def_property("signature",
        static_cast<getter_t<uint32_t>>(&ResourceFixedFileInfo::signature),
        static_cast<setter_t<uint32_t>>(&ResourceFixedFileInfo::signature),
        "Contains the value ``0xFEEF04BD``")

    .def_property("struct_version",
        static_cast<getter_t<uint32_t>>(&ResourceFixedFileInfo::struct_version),
        static_cast<setter_t<uint32_t>>(&ResourceFixedFileInfo::struct_version),
        "The binary version number of this structure.\n\n"
        "\t* The high-order word of this member contains the major version number.\n\n"
        "\t* The low-order word contains the minor version number\n\n")

    .def_property("file_version_MS",
        static_cast<getter_t<uint32_t>>(&ResourceFixedFileInfo::file_version_MS),
        static_cast<setter_t<uint32_t>>(&ResourceFixedFileInfo::file_version_MS),
        "The **most** significant 32 bits of the file's binary version number\n\n"
        "This member is used with :attr:`~lief.PE.ResourceFixedFileInfo.file_version_LS` "
        "to form a 64-bits value used for numeric comparisons.")

    .def_property("file_version_LS",
        static_cast<getter_t<uint32_t>>(&ResourceFixedFileInfo::file_version_LS),
        static_cast<setter_t<uint32_t>>(&ResourceFixedFileInfo::file_version_LS),
        "The **least** significant 32 bits of the file's binary version number\n\n"
        "This member is used with :attr:`~lief.PE.ResourceFixedFileInfo.file_version_MS` "
        "to form a 64-bits value used for numeric comparisons.")

    .def_property("product_version_MS",
        static_cast<getter_t<uint32_t>>(&ResourceFixedFileInfo::product_version_MS),
        static_cast<setter_t<uint32_t>>(&ResourceFixedFileInfo::product_version_MS),
        "The **most** significant 32 bits of the product with which this file was distributed\n\n"
        "This member is used with :attr:`~lief.PE.ResourceFixedFileInfo.product_version_LS` "
        "to form a 64-bits value used for numeric comparisons.")

    .def_property("product_version_LS",
        static_cast<getter_t<uint32_t>>(&ResourceFixedFileInfo::product_version_LS),
        static_cast<setter_t<uint32_t>>(&ResourceFixedFileInfo::product_version_LS),
        "The **least** significant 32 bits of the product with which this file was distributed\n\n"
        "This member is used with :attr:`~lief.PE.ResourceFixedFileInfo.product_version_MS` "
        "to form a 64-bits value used for numeric comparisons.")

    .def_property("file_flags_mask",
        static_cast<getter_t<uint32_t>>(&ResourceFixedFileInfo::file_flags_mask),
        static_cast<setter_t<uint32_t>>(&ResourceFixedFileInfo::file_flags_mask),
        "Contains a bitmask that specifies the valid bits in "
        ":attr:`~lief.PE.ResourceFixedFileInfo.file_flags`.\n\n"
        "A bit is valid only if it was defined when the file was created.")

    .def_property("file_flags",
        static_cast<getter_t<uint32_t>>(&ResourceFixedFileInfo::file_flags),
        static_cast<setter_t<uint32_t>>(&ResourceFixedFileInfo::file_flags),
        "Contains a bitmask that specifies the Boolean attributes of the file (" RST_CLASS_REF(lief.PE.FIXED_VERSION_FILE_FLAGS) ")")

    .def_property("file_os",
        static_cast<getter_t<FIXED_VERSION_OS>>(&ResourceFixedFileInfo::file_os),
        static_cast<setter_t<FIXED_VERSION_OS>>(&ResourceFixedFileInfo::file_os),
        "The operating system for which this file was designed (" RST_CLASS_REF(lief.PE.FIXED_VERSION_OS) ")")

    .def_property("file_type",
        static_cast<getter_t<FIXED_VERSION_FILE_TYPES>>(&ResourceFixedFileInfo::file_type),
        static_cast<setter_t<FIXED_VERSION_FILE_TYPES>>(&ResourceFixedFileInfo::file_type),
        "The general type of file (" RST_CLASS_REF(lief.PE.FIXED_VERSION_FILE_TYPES) ")")

    .def_property("file_subtype",
        static_cast<getter_t<FIXED_VERSION_FILE_SUB_TYPES>>(&ResourceFixedFileInfo::file_subtype),
        static_cast<setter_t<FIXED_VERSION_FILE_SUB_TYPES>>(&ResourceFixedFileInfo::file_subtype),
        "The function of the file (" RST_CLASS_REF(lief.PE.FIXED_VERSION_FILE_SUB_TYPES) ")")

    .def_property("file_date_MS",
        static_cast<getter_t<uint32_t>>(&ResourceFixedFileInfo::file_date_MS),
        static_cast<setter_t<uint32_t>>(&ResourceFixedFileInfo::file_date_MS),
        "The **most** significant 32 bits of the file's 64-bit binary creation date and time stamp")

    .def_property("file_date_LS",
        static_cast<getter_t<uint32_t>>(&ResourceFixedFileInfo::file_date_LS),
        static_cast<setter_t<uint32_t>>(&ResourceFixedFileInfo::file_date_LS),
        "The **least** significant 32 bits of the file's 64-bit binary creation date and time stamp")


    .def("__eq__", &ResourceFixedFileInfo::operator==)
    .def("__ne__", &ResourceFixedFileInfo::operator!=)
    .def("__hash__",
        [] (const ResourceFixedFileInfo& fixed_file_info) {
          return Hash::hash(fixed_file_info);
        })

    .def("__str__",
        [] (const ResourceFixedFileInfo& fixed_file_info) {
          std::ostringstream stream;
          stream << fixed_file_info;
          std::string str = stream.str();
          return str;
        });
}

