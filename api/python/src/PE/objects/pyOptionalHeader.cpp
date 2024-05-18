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

#include "LIEF/PE/OptionalHeader.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/operators.h>

#define PY_ENUM(x) to_string(x), x

namespace LIEF::PE::py {

template<>
void create<OptionalHeader>(nb::module_& m) {
  nb::class_<OptionalHeader, Object> opt_header(m, "OptionalHeader",
      R"delim(
      Class which represents the PE OptionalHeader structure.
      )delim"_doc);

  enum_<OptionalHeader::SUBSYSTEM>(opt_header, "SUBSYSTEM")
    .value(PY_ENUM(OptionalHeader::SUBSYSTEM::UNKNOWN))
    .value(PY_ENUM(OptionalHeader::SUBSYSTEM::NATIVE))
    .value(PY_ENUM(OptionalHeader::SUBSYSTEM::WINDOWS_GUI))
    .value(PY_ENUM(OptionalHeader::SUBSYSTEM::WINDOWS_CUI))
    .value(PY_ENUM(OptionalHeader::SUBSYSTEM::OS2_CUI))
    .value(PY_ENUM(OptionalHeader::SUBSYSTEM::POSIX_CUI))
    .value(PY_ENUM(OptionalHeader::SUBSYSTEM::NATIVE_WINDOWS))
    .value(PY_ENUM(OptionalHeader::SUBSYSTEM::WINDOWS_CE_GUI))
    .value(PY_ENUM(OptionalHeader::SUBSYSTEM::EFI_APPLICATION))
    .value(PY_ENUM(OptionalHeader::SUBSYSTEM::EFI_BOOT_SERVICE_DRIVER))
    .value(PY_ENUM(OptionalHeader::SUBSYSTEM::EFI_RUNTIME_DRIVER))
    .value(PY_ENUM(OptionalHeader::SUBSYSTEM::EFI_ROM))
    .value(PY_ENUM(OptionalHeader::SUBSYSTEM::XBOX))
    .value(PY_ENUM(OptionalHeader::SUBSYSTEM::WINDOWS_BOOT_APPLICATION));

  enum_<OptionalHeader::DLL_CHARACTERISTICS>(opt_header, "DLL_CHARACTERISTICS", nb::is_arithmetic())
    .value(PY_ENUM(OptionalHeader::DLL_CHARACTERISTICS::HIGH_ENTROPY_VA))
    .value(PY_ENUM(OptionalHeader::DLL_CHARACTERISTICS::DYNAMIC_BASE))
    .value(PY_ENUM(OptionalHeader::DLL_CHARACTERISTICS::FORCE_INTEGRITY))
    .value(PY_ENUM(OptionalHeader::DLL_CHARACTERISTICS::NX_COMPAT))
    .value(PY_ENUM(OptionalHeader::DLL_CHARACTERISTICS::NO_ISOLATION))
    .value(PY_ENUM(OptionalHeader::DLL_CHARACTERISTICS::NO_SEH))
    .value(PY_ENUM(OptionalHeader::DLL_CHARACTERISTICS::NO_BIND))
    .value(PY_ENUM(OptionalHeader::DLL_CHARACTERISTICS::APPCONTAINER))
    .value(PY_ENUM(OptionalHeader::DLL_CHARACTERISTICS::WDM_DRIVER))
    .value(PY_ENUM(OptionalHeader::DLL_CHARACTERISTICS::GUARD_CF))
    .value(PY_ENUM(OptionalHeader::DLL_CHARACTERISTICS::TERMINAL_SERVER_AWARE));

  opt_header
    .def_static("create", OptionalHeader::create, "type"_a)

    .def_prop_rw("magic",
        nb::overload_cast<>(&OptionalHeader::magic, nb::const_),
        nb::overload_cast<PE_TYPE>(&OptionalHeader::magic),
        "Magic value (" RST_CLASS_REF(lief.PE.PE_TYPE) ") that identifies a ``PE32`` from a ``PE64``"_doc)

    .def_prop_rw("major_linker_version",
        nb::overload_cast<>(&OptionalHeader::major_linker_version, nb::const_),
        nb::overload_cast<uint8_t>(&OptionalHeader::major_linker_version),
        "The linker major version number"_doc)

    .def_prop_rw("minor_linker_version",
        nb::overload_cast<>(&OptionalHeader::minor_linker_version, nb::const_),
        nb::overload_cast<uint8_t>(&OptionalHeader::minor_linker_version),
        "The linker minor version number"_doc)

    .def_prop_rw("sizeof_code",
        nb::overload_cast<>(&OptionalHeader::sizeof_code, nb::const_),
        nb::overload_cast<uint32_t>(&OptionalHeader::sizeof_code),
        R"delim(
        The size of the code ``.text`` section or the sum of
        all the sections that contain code (ie. :class:`~lief.PE.Section` with
        the flag :attr:`~lief.PE.Section.CHARACTERISTICS.CNT_CODE`)
        )delim"_doc)

    .def_prop_rw("sizeof_initialized_data",
        nb::overload_cast<>(&OptionalHeader::sizeof_initialized_data, nb::const_),
        nb::overload_cast<uint32_t>(&OptionalHeader::sizeof_initialized_data),
        R"delim(
        The size of the initialized data which are usually located in the ``.data`` section.
        If the initialized data are split across multiple sections, it is the sum of the sections.

        The sections associated with the initialized data are usually identified with the
        flag :attr:`~lief.PE.Section.CHARACTERISTICS.CNT_INITIALIZED_DATA`
        )delim"_doc)

    .def_prop_rw("sizeof_uninitialized_data",
        nb::overload_cast<>(&OptionalHeader::sizeof_uninitialized_data, nb::const_),
        nb::overload_cast<uint32_t>(&OptionalHeader::sizeof_uninitialized_data),
        R"delim(
        The size of the uninitialized data which are usually located in the ``.bss`` section.
        If the uninitialized data are split across multiple sections, it is the sum of the sections.

        The sections associated with the uninitialized data are usually identified with the
        flag :attr:`~lief.PE.Section.CHARACTERISTICS.CNT_UNINITIALIZED_DATA`
        )delim"_doc)

    .def_prop_rw("addressof_entrypoint",
        nb::overload_cast<>(&OptionalHeader::addressof_entrypoint, nb::const_),
        nb::overload_cast<uint32_t>(&OptionalHeader::addressof_entrypoint),
        R"delim(
        The address of the entry point relative to the image base when the executable file is
        loaded into memory. For program images, this is the starting address. For device
        drivers, this is the address of the initialization function.

        An entry point is optional for DLLs. When no entry point is present, this field must be zero.
        )delim"_doc)

    .def_prop_rw("baseof_code",
        nb::overload_cast<>(&OptionalHeader::baseof_code, nb::const_),
        nb::overload_cast<uint32_t>(&OptionalHeader::baseof_code),
        "Address relative to the imagebase where the binary's code starts"_doc)

    .def_prop_rw("baseof_data",
        nb::overload_cast<>(&OptionalHeader::baseof_data, nb::const_),
        nb::overload_cast<uint32_t>(&OptionalHeader::baseof_data),
        R"delim(
        Address relative to the imagebase where the binary's data starts.

        .. warning::

            This value is not present for ``PE64`` files

        )delim"_doc)

    .def_prop_rw("imagebase",
        nb::overload_cast<>(&OptionalHeader::imagebase, nb::const_),
        nb::overload_cast<uint64_t>(&OptionalHeader::imagebase),
        "The preferred base address when mapping the binary in memory"_doc)

    .def_prop_rw("section_alignment",
        nb::overload_cast<>(&OptionalHeader::section_alignment, nb::const_),
        nb::overload_cast<uint32_t>(&OptionalHeader::section_alignment),
        R"delim(
        The alignment (in bytes) of sections when they are loaded into memory.
        It must be greater than or equal to :attr:`~lief.PE.OptionalHeader.file_alignment` and
        the default is the page size for the architecture.
        )delim"_doc)

    .def_prop_rw("file_alignment",
        nb::overload_cast<>(&OptionalHeader::file_alignment, nb::const_),
        nb::overload_cast<uint32_t>(&OptionalHeader::file_alignment),
        R"delim(
        The alignment factor (in bytes) that is used to align the raw data of
        sections in the image file.
        The value should be a **power of 2** between 512 and 64K, inclusive.
        The default value is 512.
        If the :attr:`~lief.PE.OptionalHeader.section_alignment` is less than the architecture's page size,
        then :attr:`~lief.PE.OptionalHeader.file_alignment` must match :attr:`~lief.PE.OptionalHeader.section_alignment`.
        )delim"_doc)


    .def_prop_rw("major_operating_system_version",
        nb::overload_cast<>(&OptionalHeader::major_operating_system_version, nb::const_),
        nb::overload_cast<uint16_t>(&OptionalHeader::major_operating_system_version),
        "The major version number of the required operating system."_doc)

    .def_prop_rw("minor_operating_system_version",
        nb::overload_cast<>(&OptionalHeader::minor_operating_system_version, nb::const_),
        nb::overload_cast<uint16_t>(&OptionalHeader::minor_operating_system_version),
        "The minor version number of the required operating system."_doc)

    .def_prop_rw("major_image_version",
        nb::overload_cast<>(&OptionalHeader::major_image_version, nb::const_),
        nb::overload_cast<uint16_t>(&OptionalHeader::major_image_version),
        "The major version number of the image."_doc)

    .def_prop_rw("minor_image_version",
        nb::overload_cast<>(&OptionalHeader::minor_image_version, nb::const_),
        nb::overload_cast<uint16_t>(&OptionalHeader::minor_image_version),
        "The minor version number of the image."_doc)

    .def_prop_rw("major_subsystem_version",
        nb::overload_cast<>(&OptionalHeader::major_subsystem_version, nb::const_),
        nb::overload_cast<uint16_t>(&OptionalHeader::major_subsystem_version),
        "The major version number of the subsystem."_doc)

    .def_prop_rw("minor_subsystem_version",
        nb::overload_cast<>(&OptionalHeader::minor_subsystem_version, nb::const_),
        nb::overload_cast<uint16_t>(&OptionalHeader::minor_subsystem_version),
        "The minor version number of the subsystem"_doc)

    .def_prop_rw("win32_version_value",
        nb::overload_cast<>(&OptionalHeader::win32_version_value, nb::const_),
        nb::overload_cast<uint32_t>(&OptionalHeader::win32_version_value),
        "Reserved, must be zero."_doc)

    .def_prop_rw("sizeof_image",
        nb::overload_cast<>(&OptionalHeader::sizeof_image, nb::const_),
        nb::overload_cast<uint32_t>(&OptionalHeader::sizeof_image),
        R"delim(
        The size (in bytes) of the image, including all headers, as the image is loaded in memory.
        It must be a multiple of :attr:`~lief.PE.OptionalHeader.section_alignment` and should match :attr:`~lief.PE.Binary.virtual_size`.
        )delim"_doc)

    .def_prop_rw("sizeof_headers",
        nb::overload_cast<>(&OptionalHeader::sizeof_headers, nb::const_),
        nb::overload_cast<uint32_t>(&OptionalHeader::sizeof_headers),
        R"delim(
        The combined size of an MS-DOS stub, PE header, and section headers rounded up
        to a multiple of :attr:`~lief.PE.OptionalHeader.file_alignment`.
        )delim"_doc)

    .def_prop_rw("checksum",
        nb::overload_cast<>(&OptionalHeader::checksum, nb::const_),
        nb::overload_cast<uint32_t>(&OptionalHeader::checksum),
        R"delim(
        The image file checksum. The algorithm for computing the checksum is incorporated into ``IMAGHELP.DLL``.
        The following are checked for validation at load time all **drivers**, any **DLL loaded at boot**
        time, and any **DLL** that is loaded into a **critical** Windows process.
        )delim"_doc)


    .def_prop_rw("subsystem",
        nb::overload_cast<>(&OptionalHeader::subsystem, nb::const_),
        nb::overload_cast<OptionalHeader::SUBSYSTEM>(&OptionalHeader::subsystem),
        R"delim(
        Target subsystem (:class:`~lief.PE.OptionalHeader.SUBSYSTEM`) like Driver, XBox, Windows GUI, ..
        )delim"_doc)

    .def_prop_rw("dll_characteristics",
        nb::overload_cast<>(&OptionalHeader::dll_characteristics, nb::const_),
        nb::overload_cast<uint32_t>(&OptionalHeader::dll_characteristics),
        R"delim(
        Some characteristics (:class:`~lief.PE.OptionalHeader.DLL_CHARACTERISTICS`) of the underlying binary like the support of the PIE.

        The prefix ``dll`` comes from the official PE specifications but these characteristics
        are also used for **executables**
        )delim"_doc)

    .def("add",
        nb::overload_cast<OptionalHeader::DLL_CHARACTERISTICS>(&OptionalHeader::add),
        "Add the given " RST_CLASS_REF(lief.PE.OptionalHeader.DLL_CHARACTERISTICS) ""_doc,
        "characteristic"_a)

    .def("remove",
        nb::overload_cast<OptionalHeader::DLL_CHARACTERISTICS>(&OptionalHeader::remove),
        "Remove the given " RST_CLASS_REF(lief.PE.OptionalHeader.DLL_CHARACTERISTICS) ""_doc,
        "characteristic"_a)

    .def_prop_ro("dll_characteristics_lists",
        &OptionalHeader::dll_characteristics_list,
        ":attr:`~lief.PE.OptionalHeader.dll_characteristics` as a list of " RST_CLASS_REF(lief.PE.OptionalHeader.DLL_CHARACTERISTICS) ""_doc)

    .def("has",
        nb::overload_cast<OptionalHeader::DLL_CHARACTERISTICS>(&OptionalHeader::has, nb::const_),
        "``True`` if the given " RST_CLASS_REF(lief.PE.OptionalHeader.DLL_CHARACTERISTICS) " is in the "
        ":attr:`~lief.PE.OptionalHeader.dll_characteristics`"_doc,
        "characteristics"_a)

    .def_prop_rw("sizeof_stack_reserve",
        nb::overload_cast<>(&OptionalHeader::sizeof_stack_reserve, nb::const_),
        nb::overload_cast<uint64_t>(&OptionalHeader::sizeof_stack_reserve),
        R"delim(
        The size of the stack to reserve.

        Only :attr:`~lief.PE.OptionalHeader.sizeof_stack_commit` is committed, the rest is made
        available one page at a time until the reserve size is reached.
        )delim"_doc)

    .def_prop_rw("sizeof_stack_commit",
        nb::overload_cast<>(&OptionalHeader::sizeof_stack_commit, nb::const_),
        nb::overload_cast<uint64_t>(&OptionalHeader::sizeof_stack_commit),
        "The size of the stack to commit."_doc)

    .def_prop_rw("sizeof_heap_reserve",
        nb::overload_cast<>(&OptionalHeader::sizeof_heap_reserve, nb::const_),
        nb::overload_cast<uint64_t>(&OptionalHeader::sizeof_heap_reserve),
        R"delim(
        The size of the local heap space to reserve.

        Only :attr:`~lief.PE.OptionalHeader.sizeof_heap_commit` is available one page at a time until
        the reserve size is reached.
        )delim"_doc)

    .def_prop_rw("sizeof_heap_commit",
        nb::overload_cast<>(&OptionalHeader::sizeof_heap_commit, nb::const_),
        nb::overload_cast<uint64_t>(&OptionalHeader::sizeof_heap_commit),
        "The size of the local heap space to commit."_doc)

    .def_prop_rw("loader_flags",
        nb::overload_cast<>(&OptionalHeader::loader_flags, nb::const_),
        nb::overload_cast<uint32_t>(&OptionalHeader::loader_flags),
        "According to the PE specifications, this value is *reserved* and **should** be 0."_doc)

    .def_prop_rw("numberof_rva_and_size",
        nb::overload_cast<>(&OptionalHeader::numberof_rva_and_size, nb::const_),
        nb::overload_cast<uint32_t>(&OptionalHeader::numberof_rva_and_size),
        "The number of " RST_CLASS_REF(lief.PE.DataDirectory) " that follow this header"_doc)

    .def(nb::self += OptionalHeader::DLL_CHARACTERISTICS(), nb::rv_policy::reference_internal)
    .def(nb::self -= OptionalHeader::DLL_CHARACTERISTICS(), nb::rv_policy::reference_internal)

    .def("__contains__",
        nb::overload_cast<OptionalHeader::DLL_CHARACTERISTICS>(&OptionalHeader::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.PE.OptionalHeader.DLL_CHARACTERISTICS) " is present"_doc)

    LIEF_COPYABLE(OptionalHeader)
    LIEF_DEFAULT_STR(OptionalHeader);
}
}
