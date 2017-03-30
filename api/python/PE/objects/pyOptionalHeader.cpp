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

#include "LIEF/visitors/Hash.hpp"
#include "LIEF/PE/OptionalHeader.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (OptionalHeader::*)(void) const;

template<class T>
using setter_t = void (OptionalHeader::*)(T);

void init_PE_OptionalHeader_class(py::module& m) {
  py::class_<OptionalHeader>(m, "OptionalHeader")
    .def(py::init<>())
    .def_property("magic",
        static_cast<getter_t<PE_TYPE>>(&OptionalHeader::magic),
        static_cast<setter_t<PE_TYPE>>(&OptionalHeader::magic))

    .def_property("major_linker_version",
        static_cast<getter_t<uint8_t>>(&OptionalHeader::major_linker_version),
        static_cast<setter_t<uint8_t>>(&OptionalHeader::major_linker_version))

    .def_property("minor_linker_version",
        static_cast<getter_t<uint8_t>>(&OptionalHeader::minor_linker_version),
        static_cast<setter_t<uint8_t>>(&OptionalHeader::minor_linker_version))

    .def_property("sizeof_code",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::sizeof_code),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::sizeof_code))

    .def_property("sizeof_initialized_data",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::sizeof_initialized_data),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::sizeof_initialized_data))

    .def_property("sizeof_uninitialized_data",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::sizeof_uninitialized_data),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::sizeof_uninitialized_data))

    .def_property("addressof_entrypoint",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::addressof_entrypoint),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::addressof_entrypoint))

    .def_property("baseof_code",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::baseof_code),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::baseof_code))

    .def_property("baseof_data",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::baseof_data),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::baseof_data))

    .def_property("imagebase",
        static_cast<getter_t<uint64_t>>(&OptionalHeader::imagebase),
        static_cast<setter_t<uint64_t>>(&OptionalHeader::imagebase))

    .def_property("section_alignment",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::section_alignment),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::section_alignment))

    .def_property("file_alignment",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::file_alignment),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::file_alignment))

    .def_property("major_operating_system_version",
        static_cast<getter_t<uint16_t>>(&OptionalHeader::major_operating_system_version),
        static_cast<setter_t<uint16_t>>(&OptionalHeader::major_operating_system_version))

    .def_property("minor_operating_system_version",
        static_cast<getter_t<uint16_t>>(&OptionalHeader::minor_operating_system_version),
        static_cast<setter_t<uint16_t>>(&OptionalHeader::minor_operating_system_version))

    .def_property("major_image_version",
        static_cast<getter_t<uint16_t>>(&OptionalHeader::major_image_version),
        static_cast<setter_t<uint16_t>>(&OptionalHeader::major_image_version))

    .def_property("minor_image_version",
        static_cast<getter_t<uint16_t>>(&OptionalHeader::minor_image_version),
        static_cast<setter_t<uint16_t>>(&OptionalHeader::minor_image_version))

    .def_property("major_subsystem_version",
        static_cast<getter_t<uint16_t>>(&OptionalHeader::major_subsystem_version),
        static_cast<setter_t<uint16_t>>(&OptionalHeader::major_subsystem_version))

    .def_property("minor_subsystem_version",
        static_cast<getter_t<uint16_t>>(&OptionalHeader::minor_subsystem_version),
        static_cast<setter_t<uint16_t>>(&OptionalHeader::minor_subsystem_version))

    .def_property("win32_version_value",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::win32_version_value),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::win32_version_value))

    .def_property("sizeof_image",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::sizeof_image),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::sizeof_image))

    .def_property("sizeof_headers",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::sizeof_headers),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::sizeof_headers))

    .def_property("checksum",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::checksum),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::checksum))

    .def_property("subsystem",
        static_cast<getter_t<SUBSYSTEM>>(&OptionalHeader::subsystem),
        static_cast<setter_t<SUBSYSTEM>>(&OptionalHeader::subsystem))

    .def_property("dll_characteristics",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::dll_characteristics),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::dll_characteristics))

    .def_property_readonly("dll_characteristics_lists",
        &OptionalHeader::dll_characteristics_list)

    .def("has_dll_characteristics",
        &OptionalHeader::has_dll_characteristics)

    .def_property("sizeof_stack_reserve",
        static_cast<getter_t<uint64_t>>(&OptionalHeader::sizeof_stack_reserve),
        static_cast<setter_t<uint64_t>>(&OptionalHeader::sizeof_stack_reserve))

    .def_property("sizeof_stack_commit",
        static_cast<getter_t<uint64_t>>(&OptionalHeader::sizeof_stack_commit),
        static_cast<setter_t<uint64_t>>(&OptionalHeader::sizeof_stack_commit))

    .def_property("sizeof_heap_reserve",
        static_cast<getter_t<uint64_t>>(&OptionalHeader::sizeof_heap_reserve),
        static_cast<setter_t<uint64_t>>(&OptionalHeader::sizeof_heap_reserve))

    .def_property("sizeof_heap_commit",
        static_cast<getter_t<uint64_t>>(&OptionalHeader::sizeof_heap_commit),
        static_cast<setter_t<uint64_t>>(&OptionalHeader::sizeof_heap_commit))

    .def_property("loader_flags",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::loader_flags),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::loader_flags))

    .def_property("numberof_rva_and_size",
        static_cast<getter_t<uint32_t>>(&OptionalHeader::numberof_rva_and_size),
        static_cast<setter_t<uint32_t>>(&OptionalHeader::numberof_rva_and_size))


    .def("__eq__", &OptionalHeader::operator==)
    .def("__ne__", &OptionalHeader::operator!=)
    .def("__hash__",
        [] (const OptionalHeader& optional_header) {
          return LIEF::Hash::hash(optional_header);
        })

    .def("__str__", [] (const OptionalHeader& header)
        {
          std::ostringstream stream;
          stream << header;
          std::string str = stream.str();
          return str;
        });


}
