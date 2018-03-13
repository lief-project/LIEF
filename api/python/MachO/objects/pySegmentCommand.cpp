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
#include "pyMachO.hpp"


#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/SegmentCommand.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (SegmentCommand::*)(void) const;

template<class T>
using setter_t = void (SegmentCommand::*)(T);

template<class T>
using no_const_getter = T (SegmentCommand::*)(void);

void init_MachO_SegmentCommand_class(py::module& m) {

  py::class_<SegmentCommand, LoadCommand>(m, "SegmentCommand")
    .def(py::init<>())

    .def_property("name",
        [] (const SegmentCommand& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<const std::string&>>(&SegmentCommand::name),
        "Segment's name"
        )

    .def_property("virtual_address",
        static_cast<getter_t<uint64_t>>(&SegmentCommand::virtual_address),
        static_cast<setter_t<uint64_t>>(&SegmentCommand::virtual_address),
        "Segment's virtual address"
        )

    .def_property("virtual_size",
        static_cast<getter_t<uint64_t>>(&SegmentCommand::virtual_size),
        static_cast<setter_t<uint64_t>>(&SegmentCommand::virtual_size),
        "Segment's virtual size"
        )

    .def_property("file_size",
        static_cast<getter_t<uint64_t>>(&SegmentCommand::file_size),
        static_cast<setter_t<uint64_t>>(&SegmentCommand::file_size),
        "Segment's file size"
        )

    .def_property("file_offset",
        static_cast<getter_t<uint64_t>>(&SegmentCommand::file_offset),
        static_cast<setter_t<uint64_t>>(&SegmentCommand::file_offset),
        "Segment's file offset"
        )

    .def_property("max_protection",
        static_cast<getter_t<uint32_t>>(&SegmentCommand::max_protection),
        static_cast<setter_t<uint32_t>>(&SegmentCommand::max_protection),
        "Segment's max protection"
        )

    .def_property("init_protection",
        static_cast<getter_t<uint32_t>>(&SegmentCommand::init_protection),
        static_cast<setter_t<uint32_t>>(&SegmentCommand::init_protection),
        "Segment's initial protection"
        )

    .def_property("numberof_sections",
        static_cast<getter_t<uint32_t>>(&SegmentCommand::numberof_sections),
        static_cast<setter_t<uint32_t>>(&SegmentCommand::numberof_sections),
        "Number of sections in this segment"
        )

    .def_property_readonly("sections",
        static_cast<no_const_getter<it_sections>>(&SegmentCommand::sections),
        "Segment's sections"
        )

    .def_property_readonly("relocations",
        static_cast<no_const_getter<it_relocations>>(&SegmentCommand::relocations),
        "Segment's relocations"
        )

    .def_property("content",
        static_cast<getter_t<const std::vector<uint8_t>&>>(&SegmentCommand::content),
        static_cast<setter_t<const std::vector<uint8_t>&>>(&SegmentCommand::content),
        "Segment's content"
        )


    .def_property("flags",
        static_cast<getter_t<uint32_t>>(&SegmentCommand::flags),
        static_cast<setter_t<uint32_t>>(&SegmentCommand::flags),
        "Segment's flags"
        )

    .def("__eq__", &SegmentCommand::operator==)
    .def("__ne__", &SegmentCommand::operator!=)
    .def("__hash__",
        [] (const SegmentCommand& segment_command) {
          return Hash::hash(segment_command);
        })


    .def("__str__",
        [] (const SegmentCommand& segment)
        {
          std::ostringstream stream;
          stream << segment;
          std::string str =  stream.str();
          return str;
        });

}



