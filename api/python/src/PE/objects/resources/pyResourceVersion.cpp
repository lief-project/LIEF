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

#include "LIEF/PE/resources/ResourceVersion.hpp"
#include "LIEF/PE/resources/ResourceVarFileInfo.hpp"
#include "LIEF/PE/resources/ResourceStringFileInfo.hpp"

#include <string>
#include <sstream>

#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/extra/stl/u16string.h>
#include <nanobind/utils.hpp>

namespace LIEF::PE::py {

void create_fixed_file_info_t(nb::handle m) {
  using fixed_file_info_t = ResourceVersion::fixed_file_info_t;

  nb::class_<fixed_file_info_t> finfo(m, "fixed_file_info_t",
    R"doc(
    This structure represents the ``VS_FIXEDFILEINFO`` structure defined
    in ``verrsrc.h``.
    )doc"_doc
  );

  nb::enum_<fixed_file_info_t::VERSION_OS>(finfo, "VERSION_OS")
  #define ENTRY(X) .value(to_string(fixed_file_info_t::VERSION_OS::X), fixed_file_info_t::VERSION_OS::X)
    ENTRY(DOS_WINDOWS16)
    ENTRY(DOS_WINDOWS32)
    ENTRY(NT)
    ENTRY(NT_WINDOWS32)
    ENTRY(OS216)
    ENTRY(OS216_PM16)
    ENTRY(OS232)
    ENTRY(OS232_PM32)
    ENTRY(PM16)
    ENTRY(PM32)
    ENTRY(UNKNOWN)
    ENTRY(WINCE)
    ENTRY(WINDOWS16)
    ENTRY(WINDOWS32)
  #undef ENTRY
  ;

  nb::enum_<fixed_file_info_t::FILE_TYPE>(finfo, "FILE_TYPE")
  #define ENTRY(X) .value(to_string(fixed_file_info_t::FILE_TYPE::X), fixed_file_info_t::FILE_TYPE::X)
    ENTRY(UNKNOWN)
    ENTRY(APP)
    ENTRY(DLL)
    ENTRY(DRV)
    ENTRY(FONT)
    ENTRY(STATIC_LIB)
    ENTRY(VXD)
  #undef ENTRY
  ;

  nb::enum_<fixed_file_info_t::FILE_FLAGS>(finfo, "FILE_FLAGS")
  #define ENTRY(X) .value(to_string(fixed_file_info_t::FILE_FLAGS::X), fixed_file_info_t::FILE_FLAGS::X)
    ENTRY(DEBUG)
    ENTRY(INFO_INFERRED)
    ENTRY(PATCHED)
    ENTRY(PRERELEASE)
    ENTRY(PRIVATEBUILD)
    ENTRY(SPECIALBUILD)
  #undef ENTRY
  ;

  nb::enum_<fixed_file_info_t::FILE_TYPE_DETAILS>(finfo, "FILE_TYPE_DETAILS")
  #define ENTRY(X) .value(to_string(fixed_file_info_t::FILE_TYPE_DETAILS::X), fixed_file_info_t::FILE_TYPE_DETAILS::X)
    ENTRY(DRV_COMM)
    ENTRY(DRV_DISPLAY)
    ENTRY(DRV_INPUTMETHOD)
    ENTRY(DRV_INSTALLABLE)
    ENTRY(DRV_KEYBOARD)
    ENTRY(DRV_LANGUAGE)
    ENTRY(DRV_MOUSE)
    ENTRY(DRV_NETWORK)
    ENTRY(DRV_PRINTER)
    ENTRY(DRV_SOUND)
    ENTRY(DRV_SYSTEM)
    ENTRY(DRV_VERSIONED_PRINTER)
    ENTRY(FONT_RASTER)
    ENTRY(FONT_TRUETYPE)
    ENTRY(FONT_VECTOR)
    ENTRY(UNKNOWN)
  #undef ENTRY
  ;
  finfo
    .def_rw("signature", &fixed_file_info_t::signature,
      R"doc(
      Contains the value ``0xFEEF04BD``. This is used with the ``szKey`` member of
      the ``VS_VERSIONINFO`` structure when searching a file for the
      ``VS_FIXEDFILEINFO`` structure.
      )doc"_doc)

    .def_rw("struct_version", &fixed_file_info_t::struct_version,
      R"doc(
      The binary version number of this structure. The high-order word of
      this member contains the major version number, and the low-order word
      contains the minor version number.
      )doc"_doc)

    .def_rw("file_version_ms", &fixed_file_info_t::file_version_ms,
      R"doc(
      The most significant 32 bits of the file's binary version number.
      This member is used with :attr:`~.file_version_ls` to form a 64-bit value
      used for numeric comparisons.
      )doc"_doc)

    .def_rw("file_version_ls", &fixed_file_info_t::file_version_ls,
      R"doc(
      The least significant 32 bits of the file's binary version number.
      This member is used with :attr:`~.file_version_ms` to form a 64-bit value
      used for numeric comparisons.
      )doc"_doc)

    .def_rw("product_version_ms", &fixed_file_info_t::product_version_ms,
      R"doc(
      The most significant 32 bits of the binary version number of the product
      with which this file was distributed. This member is used with
      :attr:`~.product_version_ls` to form a 64-bit value used for numeric
      comparisons.
      )doc"_doc)

    .def_rw("product_version_ls", &fixed_file_info_t::product_version_ls,
      R"doc(
      The least significant 32 bits of the binary version number of the product
      with which this file was distributed. This member is used with
      :attr:`~.product_version_ms` to form a 64-bit value used for numeric
      comparisons.
      )doc"_doc)

    .def_rw("file_flags_mask", &fixed_file_info_t::file_flags_mask,
      R"doc(
      Contains a bitmask that specifies the valid bits in file_flags.
      A bit is valid only if it was defined when the file was created.
      )doc"_doc)

    .def_rw("file_flags", &fixed_file_info_t::file_flags,
      R"doc(
      Contains a bitmask that specifies the Boolean attributes of the file.
      This member can include one or more of the values specified in
      :class:`~.FILE_FLAGS`.
      )doc"_doc)

    .def_rw("file_os", &fixed_file_info_t::file_os,
      R"doc(
      The operating system for which this file was designed. This member can
      be one of the values specified in :class:`~.VERSION_OS`.
      )doc"_doc)

    .def_rw("file_type", &fixed_file_info_t::file_type,
      R"doc(
      The general type of file. This member can be one of the values specified
      in :class:`~.FILE_TYPE`. All other values are reserved.
      )doc"_doc)

    .def_rw("file_subtype", &fixed_file_info_t::file_subtype,
      R"doc(
      The function of the file. The possible values depend on the value of
      file_type.
      )doc"_doc)

    .def_rw("file_date_ms", &fixed_file_info_t::file_date_ms,
      R"doc(
      The most significant 32 bits of the file's 64-bit binary creation date
      and time stamp.
      )doc"_doc)

    .def_rw("file_date_ls", &fixed_file_info_t::file_date_ls,
      R"doc(
      The least significant 32 bits of the file's 64-bit binary creation date
      and time stamp.
      )doc"_doc)

    .def("has", &fixed_file_info_t::has,
         "Check if the given flag is present"_doc, "flag"_a)

    .def_prop_ro("flags", &fixed_file_info_t::flags,
                 "List of flags"_doc)

    .def_prop_ro("file_type_details", &fixed_file_info_t::file_type_details)

    LIEF_DEFAULT_STR(fixed_file_info_t);
}

template<>
void create<ResourceVersion>(nb::module_& m) {
  nb::class_<ResourceVersion, LIEF::Object> rv(m, "ResourceVersion",
    R"delim(
    Class that represents the data associated with the ``RT_VERSION`` entry

    See: VS_VERSIONINFO -- https://docs.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo
    )delim"_doc);

  create_fixed_file_info_t(rv);

  rv
    .def_prop_ro("key", nb::overload_cast<>(&ResourceVersion::key, nb::const_),
                 R"doc(The Unicode string `L"VS_VERSION_INFO"`")doc"_doc)
    .def_prop_ro("type", nb::overload_cast<>(&ResourceVersion::type, nb::const_),
      R"doc(
      The type of data in the version resource:
        * ``1`` if it contains text data
        * ``0`` if it contains binary data
      )doc"_doc)

    .def_prop_ro("file_info", nb::overload_cast<>(&ResourceVersion::file_info, nb::const_),
                 "Return the fixed file info (``VS_FIXEDFILEINFO``)"_doc)

    .def_prop_ro("string_file_info", nb::overload_cast<>(&ResourceVersion::string_file_info, nb::const_),
                 "Return the ``StringFileInfo`` element"_doc)

    .def_prop_ro("var_file_info", nb::overload_cast<>(&ResourceVersion::var_file_info, nb::const_),
                 "Return the ``VarFileInfo`` element"_doc)
    LIEF_DEFAULT_STR(ResourceVersion);
}

}

