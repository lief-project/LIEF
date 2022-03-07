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
#include "LIEF/PE/OptionalHeader.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (OptionalHeader::*)(void) const;

template<class T>
using setter_t = void (OptionalHeader::*)(T);


template<>
void create<OptionalHeader>(py::module& m) {
  py::class_<OptionalHeader, LIEF::Object>(m, "OptionalHeader",
      R"delim(
      Class which represents the PE OptionalHeader structure..
      )delim")
    .def(py::init<>())
    .def_property("magic",
        static_cast<getter_t<PE_TYPE>>(&OptionalHeader::magic),
        static_cast<setter_t<PE_TYPE>>(&OptionalHeader::magic),
        "Magic value (" RST_CLASS_REF(lief.PE.PE_TYPE) ") that identifies a ``PE32`` from a ``PE64``")

    .def_property("major_linker_version",
        static_cast<getter_t<uint8_t>>(&OptionalHeader::major_linker_version),
        static_cast<setter_t<uint8_t>>(&OptionalHeader::major_linker_version),
        "The linker major version number")

    .def_property("minor_linker_version",
        static_cast<getter_t<uint8_t>>(&OptionalHeader::minor_linker_version),
        static_cast<setter_t<uint8_t>>(&OptionalHeader::minor_linker_version),
        "The linker minor version number")

    .def_property("sizeof_code",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::sizeof_code),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::sizeof_code),
        R"delim(
        The size of the code ``.text`` section or the sum of
        all the sections that contain code (ie. :class:`~lief.PE.Section` with the flag :attr:`~lief.PE.SECTION_CHARACTERISTICS.CNT_CODE`)
        )delim")

    .def_property("sizeof_initialized_data",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::sizeof_initialized_data),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::sizeof_initialized_data),
        R"delim(
        The size of the initialized data which are usually located in the ``.data`` section.
        If the initialized data are split across multiple sections, it is the sum of the sections.

        The sections associated with the initialized data are usually identified with the
        flag :attr:`~lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA`
        )delim")

    .def_property("sizeof_uninitialized_data",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::sizeof_uninitialized_data),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::sizeof_uninitialized_data),
        R"delim(
        The size of the uninitialized data which are usually located in the ``.bss`` section.
        If the uninitialized data are split across multiple sections, it is the sum of the sections.

        The sections associated with the uninitialized data are usually identified with the
        flag :attr:`~lief.PE.SECTION_CHARACTERISTICS.CNT_UNINITIALIZED_DATA`
        )delim")

    .def_property("addressof_entrypoint",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::addressof_entrypoint),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::addressof_entrypoint),
        R"delim(
        The address of the entry point relative to the image base when the executable file is
        loaded into memory. For program images, this is the starting address. For device
        drivers, this is the address of the initialization function.

        An entry point is optional for DLLs. When no entry point is present, this field must be zero.
        )delim")

    .def_property("baseof_code",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::baseof_code),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::baseof_code),
        "Address relative to the imagebase where the binary's code starts")

    .def_property("baseof_data",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::baseof_data),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::baseof_data),
        R"delim(
        Address relative to the imagebase where the binary's data starts.

        .. warning::

            This value is not present for ``PE64`` files

        )delim")

    .def_property("imagebase",
        static_cast<getter_t<uint64_t>>(&OptionalHeader::imagebase),
        static_cast<setter_t<uint64_t>>(&OptionalHeader::imagebase),
        "The preferred base address when mapping the binary in memory")

    .def_property("section_alignment",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::section_alignment),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::section_alignment),
        R"delim(
        The alignment (in bytes) of sections when they are loaded into memory.
        It must be greater than or equal to :attr:`~lief.PE.OptionalHeader.file_alignment` and
        the default is the page size for the architecture.
        )delim")

    .def_property("file_alignment",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::file_alignment),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::file_alignment),
        R"delim(
        The alignment factor (in bytes) that is used to align the raw data of
        sections in the image file.
        The value should be a **power of 2** between 512 and 64K, inclusive.
        The default value is 512.
        If the :attr:`~lief.PE.OptionalHeader.section_alignment` is less than the architecture's page size,
        then :attr:`~lief.PE.OptionalHeader.file_alignment` must match :attr:`~lief.PE.OptionalHeader.section_alignment`.
        )delim")


    .def_property("major_operating_system_version",
        static_cast<getter_t<uint16_t>>(&OptionalHeader::major_operating_system_version),
        static_cast<setter_t<uint16_t>>(&OptionalHeader::major_operating_system_version),
        "The major version number of the required operating system.")

    .def_property("minor_operating_system_version",
        static_cast<getter_t<uint16_t>>(&OptionalHeader::minor_operating_system_version),
        static_cast<setter_t<uint16_t>>(&OptionalHeader::minor_operating_system_version),
        "The minor version number of the required operating system.")

    .def_property("major_image_version",
        static_cast<getter_t<uint16_t>>(&OptionalHeader::major_image_version),
        static_cast<setter_t<uint16_t>>(&OptionalHeader::major_image_version),
        "The major version number of the image.")

    .def_property("minor_image_version",
        static_cast<getter_t<uint16_t>>(&OptionalHeader::minor_image_version),
        static_cast<setter_t<uint16_t>>(&OptionalHeader::minor_image_version),
        "The minor version number of the image.")

    .def_property("major_subsystem_version",
        static_cast<getter_t<uint16_t>>(&OptionalHeader::major_subsystem_version),
        static_cast<setter_t<uint16_t>>(&OptionalHeader::major_subsystem_version),
        "The major version number of the subsystem.")

    .def_property("minor_subsystem_version",
        static_cast<getter_t<uint16_t>>(&OptionalHeader::minor_subsystem_version),
        static_cast<setter_t<uint16_t>>(&OptionalHeader::minor_subsystem_version),
        "The minor version number of the subsystem")

    .def_property("win32_version_value",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::win32_version_value),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::win32_version_value),
        "Reserved, must be zero.")

    .def_property("sizeof_image",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::sizeof_image),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::sizeof_image),
        R"delim(
        The size (in bytes) of the image, including all headers, as the image is loaded in memory.
        It must be a multiple of :attr:`~lief.PE.OptionalHeader.section_alignment` and should match :attr:`~lief.PE.Binary.virtual_size`.
        )delim")

    .def_property("sizeof_headers",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::sizeof_headers),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::sizeof_headers),
        R"delim(
        The combined size of an MS-DOS stub, PE header, and section headers rounded up
        to a multiple of :attr:`~lief.PE.OptionalHeader.file_alignment`.
        )delim")

    .def_property("checksum",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::checksum),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::checksum),
        R"delim(
        The image file checksum. The algorithm for computing the checksum is incorporated into ``IMAGHELP.DLL``.
        The following are checked for validation at load time all **drivers**, any **DLL loaded at boot**
        time, and any **DLL** that is loaded into a **critical** Windows process.
        )delim")


    .def_property_readonly("computed_checksum",
        &OptionalHeader::computed_checksum,
        R"delim(
        The re-computed value of the :attr:`~lief.PE.OptionalHeader.checksum`.
        If both values do not match, it could mean that the binary has been modified
        after the compilation.

        This value is computed by LIEF when parsing the PE binary.
        )delim")

    .def_property("subsystem",
        static_cast<getter_t<SUBSYSTEM>>(&OptionalHeader::subsystem),
        static_cast<setter_t<SUBSYSTEM>>(&OptionalHeader::subsystem),
        R"delim(
        Target subsystem (:class:`~lief.PE.SUBSYSTEM`) like Driver, XBox, Windows GUI, ..
        )delim")

    .def_property("dll_characteristics",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::dll_characteristics),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::dll_characteristics),
        R"delim(
        Some characteristics (:class:`~lief.PE.DLL_CHARACTERISTICS`) of the underlying binary like the support of the PIE.

        The prefix ``dll`` comes from the official PE specifications but these characteristics
        are also used for **executables**
        )delim")

    .def("add",
        static_cast<void (OptionalHeader::*)(DLL_CHARACTERISTICS)>(&OptionalHeader::add),
        "Add the given " RST_CLASS_REF(lief.PE.DLL_CHARACTERISTICS) "",
        "characteristic"_a)

    .def("remove",
        static_cast<void (OptionalHeader::*)(DLL_CHARACTERISTICS)>(&OptionalHeader::remove),
        "Remove the given " RST_CLASS_REF(lief.PE.DLL_CHARACTERISTICS) "",
        "characteristic"_a)

    .def_property_readonly("dll_characteristics_lists",
        &OptionalHeader::dll_characteristics_list,
        ":attr:`~lief.PE.OptionalHeader.dll_characteristics` as a list of " RST_CLASS_REF(lief.PE.DLL_CHARACTERISTICS) "")

    .def("has",
        static_cast<bool (OptionalHeader::*)(DLL_CHARACTERISTICS) const>(&OptionalHeader::has),
        "``True`` if the given " RST_CLASS_REF(lief.PE.DLL_CHARACTERISTICS) " is in the "
        ":attr:`~lief.PE.OptionalHeader.dll_characteristics`",
        "characteristics"_a)

    .def_property("sizeof_stack_reserve",
        static_cast<getter_t<uint64_t>>(&OptionalHeader::sizeof_stack_reserve),
        static_cast<setter_t<uint64_t>>(&OptionalHeader::sizeof_stack_reserve),
        R"delim(
        The size of the stack to reserve.

        Only :attr:`~lief.PE.OptionalHeader.sizeof_stack_commit` is committed, the rest is made
        available one page at a time until the reserve size is reached.
        )delim")

    .def_property("sizeof_stack_commit",
        static_cast<getter_t<uint64_t>>(&OptionalHeader::sizeof_stack_commit),
        static_cast<setter_t<uint64_t>>(&OptionalHeader::sizeof_stack_commit),
        "The size of the stack to commit.")

    .def_property("sizeof_heap_reserve",
        static_cast<getter_t<uint64_t>>(&OptionalHeader::sizeof_heap_reserve),
        static_cast<setter_t<uint64_t>>(&OptionalHeader::sizeof_heap_reserve),
        R"delim(
        The size of the local heap space to reserve.

        Only :attr:`~lief.PE.OptionalHeader.sizeof_heap_commit` is available one page at a time until
        the reserve size is reached.
        )delim")

    .def_property("sizeof_heap_commit",
        static_cast<getter_t<uint64_t>>(&OptionalHeader::sizeof_heap_commit),
        static_cast<setter_t<uint64_t>>(&OptionalHeader::sizeof_heap_commit),
        "The size of the local heap space to commit.")

    .def_property("loader_flags",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::loader_flags),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::loader_flags),
        "According to the PE specifications, this value is *reserved* and **should** be 0.")

    .def_property("numberof_rva_and_size",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::numberof_rva_and_size),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::numberof_rva_and_size),
        "The number of " RST_CLASS_REF(lief.PE.DataDirectory) " that follow this header")

    .def("__eq__", &OptionalHeader::operator==)
    .def("__ne__", &OptionalHeader::operator!=)
    .def("__hash__",
        [] (const OptionalHeader& optional_header) {
          return Hash::hash(optional_header);
        })

    .def(py::self += DLL_CHARACTERISTICS())
    .def(py::self -= DLL_CHARACTERISTICS())

    .def("__contains__",
        static_cast<bool (OptionalHeader::*)(DLL_CHARACTERISTICS) const>(&OptionalHeader::has),
        "Check if the given " RST_CLASS_REF(lief.PE.DLL_CHARACTERISTICS) " is present")

    .def("__str__", [] (const OptionalHeader& header)
        {
          std::ostringstream stream;
          stream << header;
          std::string str = stream.str();
          return str;
        });
}
}
}
