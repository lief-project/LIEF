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
#include "LIEF/PE/OptionalHeader.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (OptionalHeader::*)(void) const;

template<class T>
using setter_t = void (OptionalHeader::*)(T);

void init_PE_OptionalHeader_class(py::module& m) {
  py::class_<OptionalHeader, LIEF::Object>(m, "OptionalHeader")
    .def(py::init<>())
    .def_property("magic",
        static_cast<getter_t<PE_TYPE>>(&OptionalHeader::magic),
        static_cast<setter_t<PE_TYPE>>(&OptionalHeader::magic),
        "Magic value (" RST_CLASS_REF(lief.PE.PE_TYPE) ") that identify a ``PE32`` from a ``PE64``")

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
        "The size of the code (text) section, or the "
        "sum of all code sections if there are "
        "multiple sections.")

    .def_property("sizeof_initialized_data",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::sizeof_initialized_data),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::sizeof_initialized_data),
        "The size of the initialized data section, or "
        "the sum of all such sections if there are "
        "multiple data sections.")

    .def_property("sizeof_uninitialized_data",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::sizeof_uninitialized_data),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::sizeof_uninitialized_data),
        "The size of the uninitialized data section "
        "(``.bss``), or the sum of all such sections if "
        "there are multiple ``.bss`` sections.")

    .def_property("addressof_entrypoint",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::addressof_entrypoint),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::addressof_entrypoint),
        "The address of the entry point relative to "
        "the image base when the executable file is "
        "loaded into memory. For program images, "
        "this is the starting address. For device "
        "drivers, this is the address of the "
        "initialization function. An entry point is "
        "optional for DLLs. When no entry point is "
        "present, this field must be zero.")

    .def_property("baseof_code",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::baseof_code),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::baseof_code),
        "The address that is relative to the image "
        "base of the beginning-of-code section "
        "when it is loaded into memory.")

    .def_property("baseof_data",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::baseof_data),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::baseof_data),
        "The address that is relative to the image "
        "base of the beginning-of-data section "
        "when it is loaded into memory.\n\n"
        ".. warning:: This value is not present for ``PE64``")

    .def_property("imagebase",
        static_cast<getter_t<uint64_t>>(&OptionalHeader::imagebase),
        static_cast<setter_t<uint64_t>>(&OptionalHeader::imagebase),
        "The preferred address of the first "
        "byte of image when loaded into "
        "memory. It must be a multiple of ``64K``. "
        "The default for DLLs is ``0x10000000``. "
        "The default for Windows CE EXEs "
        "is ``0x00010000``. The default for "
        "Windows NT, Windows 2000, "
        "Windows XP, Windows 95, "
        "Windows 98, and Windows Me is "
        "``0x00400000``. ")

    .def_property("section_alignment",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::section_alignment),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::section_alignment),
        "The alignment (in bytes) of sections "
        "when they are loaded into memory. "
        "It must be greater than or equal to "
        ":attr:`~lief.PE.OptionalHeader.file_alignment`. The default is the "
        "page size for the architecture.")

    .def_property("file_alignment",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::file_alignment),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::file_alignment),
        "The alignment factor (in bytes) that "
        "is used to align the raw data of "
        "sections in the image file. The value "
        "should be a **power of 2** between 512 "
        "and 64 K, inclusive. The default is "
        "512. If the :attr:`~lief.PE.OptionalHeader.section_alignment` is less "
        "than the architecture’s page size, "
        "then :attr:`~lief.PE.OptionalHeader.file_alignment` must match "
        ":attr:`~lief.PE.OptionalHeader.section_alignment`.")

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
        "The size (in bytes) of the image, "
        "including all headers, as the image "
        "is loaded in memory. It must be a "
        "multiple of :attr:`~lief.PE.OptionalHeader.section_alignment` and should match :attr:`~lief.PE.Binary.virtual_size`.")

    .def_property("sizeof_headers",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::sizeof_headers),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::sizeof_headers),
        "The combined size of an MS-DOS "
        "stub, PE header, and section "
        "headers rounded up to a multiple of "
        ":attr:`~lief.PE.OptionalHeader.file_alignment`.")

    .def_property("checksum",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::checksum),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::checksum),
        "The image file checksum. The "
        "algorithm for computing the "
        "checksum is incorporated into "
        "``IMAGHELP.DLL``. The following are "
        "checked for validation at load time: "
        "all **drivers**, any **DLL loaded at boot** "
        "time, and any **DLL** that is loaded "
        "into a **critical** Windows process.")

    .def_property("subsystem",
        static_cast<getter_t<SUBSYSTEM>>(&OptionalHeader::subsystem),
        static_cast<setter_t<SUBSYSTEM>>(&OptionalHeader::subsystem),
        "The " RST_CLASS_REF(lief.PE.SUBSYSTEM) " that is required to "
        "run this image. For more "
        "information, see “Windows "
        "Subsystem” later in this "
        "specification.")

    .def_property("dll_characteristics",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::dll_characteristics),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::dll_characteristics),
        "The " RST_CLASS_REF(lief.PE.DLL_CHARACTERISTICS) " characteristics")

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
        "" RST_CLASS_REF(lief.PE.DLL_CHARACTERISTICS) " as a list")

    .def("has",
        static_cast<bool (OptionalHeader::*)(DLL_CHARACTERISTICS) const>(&OptionalHeader::has),
        "``True`` if the given " RST_CLASS_REF(lief.PE.DLL_CHARACTERISTICS) " is in the "
        ":attr:`~lief.PE.OptionalHeader.dll_characteristics`",
        "characteristics"_a)

    .def_property("sizeof_stack_reserve",
        static_cast<getter_t<uint64_t>>(&OptionalHeader::sizeof_stack_reserve),
        static_cast<setter_t<uint64_t>>(&OptionalHeader::sizeof_stack_reserve),
        "The size of the stack to reserve. "
        "Only :attr:`~lief.PE.OptionalHeader.sizeof_stack_commit` is "
        "committed; the rest is made "
        "available one page at a time until "
        "the reserve size is reached. ")

    .def_property("sizeof_stack_commit",
        static_cast<getter_t<uint64_t>>(&OptionalHeader::sizeof_stack_commit),
        static_cast<setter_t<uint64_t>>(&OptionalHeader::sizeof_stack_commit),
        "The size of the stack to commit.")

    .def_property("sizeof_heap_reserve",
        static_cast<getter_t<uint64_t>>(&OptionalHeader::sizeof_heap_reserve),
        static_cast<setter_t<uint64_t>>(&OptionalHeader::sizeof_heap_reserve),
        "The size of the local heap space to "
        "reserve. Only :attr:`~lief.PE.OptionalHeader.sizeof_heap_commit` is "
        "committed; the rest is made "
        "available one page at a time until "
        "the reserve size is reached.")

    .def_property("sizeof_heap_commit",
        static_cast<getter_t<uint64_t>>(&OptionalHeader::sizeof_heap_commit),
        static_cast<setter_t<uint64_t>>(&OptionalHeader::sizeof_heap_commit),
        "The size of the local heap space to commit.")

    .def_property("loader_flags",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::loader_flags),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::loader_flags),
        "Reserved, must be zero.")

    .def_property("numberof_rva_and_size",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::numberof_rva_and_size),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::numberof_rva_and_size),
        "The number of " RST_CLASS_REF(lief.PE.DataDirectory) " "
        "entries in the remainder of the "
        "optional header. Each describes a "
        "location and size.")


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
