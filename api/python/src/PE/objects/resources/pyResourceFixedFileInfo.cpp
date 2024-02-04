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

#include "LIEF/PE/resources/ResourceFixedFileInfo.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<ResourceFixedFileInfo>(nb::module_& m) {
  nb::class_<ResourceFixedFileInfo, LIEF::Object>(m, "ResourceFixedFileInfo",
      R"delim(
      Representation of the `VS_FIXEDFILEINFO <https://docs.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo>`_
      structure
      )delim"_doc)

    .def_prop_rw("signature",
        nb::overload_cast<>(&ResourceFixedFileInfo::signature, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceFixedFileInfo::signature),
        "Must be set to ``0xFEEF04BD``"_doc)

    .def_prop_rw("struct_version",
        nb::overload_cast<>(&ResourceFixedFileInfo::struct_version, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceFixedFileInfo::struct_version),
        R"delim(
        The binary version number of this structure.

        * The high-order word of this member contains the major version number.
        * The low-order word contains the minor version number
        )delim"_doc)

    .def_prop_rw("file_version_MS",
        nb::overload_cast<>(&ResourceFixedFileInfo::file_version_MS, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceFixedFileInfo::file_version_MS),
        R"delim(
        The **most** significant 32 bits of the file's binary version number

        This member is used with :attr:`~lief.PE.ResourceFixedFileInfo.file_version_LS`
        to form a 64-bits value used for numeric comparisons.
        )delim"_doc)

    .def_prop_rw("file_version_LS",
        nb::overload_cast<>(&ResourceFixedFileInfo::file_version_LS, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceFixedFileInfo::file_version_LS),
        R"delim(
        The **least** significant 32 bits of the file's binary version number

        This member is used with :attr:`~lief.PE.ResourceFixedFileInfo.file_version_MS`
        to form a 64-bits value used for numeric comparisons.
        )delim"_doc)

    .def_prop_rw("product_version_MS",
        nb::overload_cast<>(&ResourceFixedFileInfo::product_version_MS, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceFixedFileInfo::product_version_MS),
        R"delim(
        The **most** significant 32 bits of the product with which this file was distributed

        This member is used with :attr:`~lief.PE.ResourceFixedFileInfo.product_version_LS`
        to form a 64-bits value used for numeric comparisons.
        )delim"_doc)

    .def_prop_rw("product_version_LS",
        nb::overload_cast<>(&ResourceFixedFileInfo::product_version_LS, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceFixedFileInfo::product_version_LS),
        R"delim(
        The **least** significant 32 bits of the product with which this file was distributed

        This member is used with :attr:`~lief.PE.ResourceFixedFileInfo.product_version_MS`
        to form a 64-bits value used for numeric comparisons.
        )delim"_doc)

    .def_prop_rw("file_flags_mask",
        nb::overload_cast<>(&ResourceFixedFileInfo::file_flags_mask, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceFixedFileInfo::file_flags_mask),
        R"delim(
        Contains a bitmask that specifies the valid bits in :attr:`~lief.PE.ResourceFixedFileInfo.file_flags`.
        A bit is valid only if it was defined when the file was created.
        )delim"_doc)

    .def_prop_rw("file_flags",
        nb::overload_cast<>(&ResourceFixedFileInfo::file_flags, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceFixedFileInfo::file_flags),
        "Contains a bitmask that specifies the Boolean attributes of the file (" RST_CLASS_REF(lief.PE.FIXED_VERSION_FILE_FLAGS) ")"_doc)

    .def_prop_rw("file_os",
        nb::overload_cast<>(&ResourceFixedFileInfo::file_os, nb::const_),
        nb::overload_cast<FIXED_VERSION_OS>(&ResourceFixedFileInfo::file_os),
        "The operating system for which this file was designed (" RST_CLASS_REF(lief.PE.FIXED_VERSION_OS) ")"_doc)

    .def_prop_rw("file_type",
        nb::overload_cast<>(&ResourceFixedFileInfo::file_type, nb::const_),
        nb::overload_cast<FIXED_VERSION_FILE_TYPES>(&ResourceFixedFileInfo::file_type),
        "The general type of file (" RST_CLASS_REF(lief.PE.FIXED_VERSION_FILE_TYPES) ")"_doc)

    .def_prop_rw("file_subtype",
        nb::overload_cast<>(&ResourceFixedFileInfo::file_subtype, nb::const_),
        nb::overload_cast<FIXED_VERSION_FILE_SUB_TYPES>(&ResourceFixedFileInfo::file_subtype),
        "The function of the file (" RST_CLASS_REF(lief.PE.FIXED_VERSION_FILE_SUB_TYPES) ")"_doc)

    .def_prop_rw("file_date_MS",
        nb::overload_cast<>(&ResourceFixedFileInfo::file_date_MS, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceFixedFileInfo::file_date_MS),
        "The **most** significant 32 bits of the file's 64-bit binary creation date and time stamp"_doc)

    .def_prop_rw("file_date_LS",
        nb::overload_cast<>(&ResourceFixedFileInfo::file_date_LS, nb::const_),
        nb::overload_cast<uint32_t>(&ResourceFixedFileInfo::file_date_LS),
        "The **least** significant 32 bits of the file's 64-bit binary creation date and time stamp"_doc)

    LIEF_DEFAULT_STR(ResourceFixedFileInfo);

}

}

