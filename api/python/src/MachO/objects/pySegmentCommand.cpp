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
#include "MachO/pyMachO.hpp"
#include "pyIterator.hpp"
#include "pySafeString.hpp"
#include "nanobind/extra/memoryview.hpp"

#include "LIEF/MachO/SegmentCommand.hpp"
#include "LIEF/MachO/Section.hpp"
#include "LIEF/MachO/Relocation.hpp"
#include "LIEF/MachO/LinkEdit.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include "enums_wrapper.hpp"

namespace LIEF::MachO::py {

template<>
void create<SegmentCommand>(nb::module_& m) {
  using namespace LIEF::py;


  nb::class_<SegmentCommand, LoadCommand> seg_cmd(m, "SegmentCommand",
      R"delim(
      Class which represents a :attr:`~.LoadCommand.TYPE.SEGMENT` /
      :attr:`~.LoadCommand.TYPE.SEGMENT_64` command
      )delim"_doc);

    init_ref_iterator<SegmentCommand::it_sections>(seg_cmd, "it_sections");

  try {
    /*
     * it_relocations could be already registered by the Section
     */
    init_ref_iterator<SegmentCommand::it_relocations>(seg_cmd, "it_relocations");
  } catch (const std::runtime_error&) { }

  enum_<SegmentCommand::VM_PROTECTIONS>(seg_cmd, "VM_PROTECTIONS")
  #define PY_ENUM(x) to_string(x), x
    .value(PY_ENUM(SegmentCommand::VM_PROTECTIONS::READ))
    .value(PY_ENUM(SegmentCommand::VM_PROTECTIONS::WRITE))
    .value(PY_ENUM(SegmentCommand::VM_PROTECTIONS::EXECUTE))
  #undef PY_ENUM
  ;

  enum_<SegmentCommand::FLAGS>(seg_cmd, "FLAGS")
  #define PY_ENUM(x) to_string(x), x
    .value(PY_ENUM(SegmentCommand::FLAGS::HIGHVM))
    .value(PY_ENUM(SegmentCommand::FLAGS::FVMLIB))
    .value(PY_ENUM(SegmentCommand::FLAGS::NORELOC))
    .value(PY_ENUM(SegmentCommand::FLAGS::PROTECTED_VERSION_1))
    .value(PY_ENUM(SegmentCommand::FLAGS::READ_ONLY))
  #undef PY_ENUM
  ;

  seg_cmd
    .def(nb::init<>())
    .def(nb::init<const std::string&>())
    .def(nb::init<const std::string&, const SegmentCommand::content_t&>())

    .def_prop_rw("name",
        [] (const SegmentCommand& obj) {
          return safe_string(obj.name());
        },
        nb::overload_cast<std::string>(&SegmentCommand::name),
        "Segment's name"_doc)

    .def_prop_rw("virtual_address",
        nb::overload_cast<>(&SegmentCommand::virtual_address, nb::const_),
        nb::overload_cast<uint64_t>(&SegmentCommand::virtual_address),
        "Segment's virtual address"_doc)

    .def_prop_rw("virtual_size",
        nb::overload_cast<>(&SegmentCommand::virtual_size, nb::const_),
        nb::overload_cast<uint64_t>(&SegmentCommand::virtual_size),
        "Segment's virtual size"_doc)

    .def_prop_rw("file_size",
        nb::overload_cast<>(&SegmentCommand::file_size, nb::const_),
        nb::overload_cast<uint64_t>(&SegmentCommand::file_size),
        "Segment's file size"_doc)

    .def_prop_rw("file_offset",
        nb::overload_cast<>(&SegmentCommand::file_offset, nb::const_),
        nb::overload_cast<uint64_t>(&SegmentCommand::file_offset),
        "Segment's file offset"_doc)

    .def_prop_rw("max_protection",
        nb::overload_cast<>(&SegmentCommand::max_protection, nb::const_),
        nb::overload_cast<uint32_t>(&SegmentCommand::max_protection),
        "Segment's max protection"_doc)

    .def_prop_rw("init_protection",
        nb::overload_cast<>(&SegmentCommand::init_protection, nb::const_),
        nb::overload_cast<uint32_t>(&SegmentCommand::init_protection),
        "Segment's initial protection"_doc)

    .def_prop_rw("numberof_sections",
        nb::overload_cast<>(&SegmentCommand::numberof_sections, nb::const_),
        nb::overload_cast<uint32_t>(&SegmentCommand::numberof_sections),
        "Number of sections in this segment"_doc)

    .def_prop_ro("sections", nb::overload_cast<>(&SegmentCommand::sections),
        "Segment's sections"_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("relocations",
        nb::overload_cast<>(&SegmentCommand::relocations),
        "Segment's relocations"_doc,
        nb::keep_alive<0, 1>())

    .def_prop_ro("index", &SegmentCommand::index,
        "Relative index of the segment in the segment table"_doc)

    .def_prop_rw("content",
        [] (const SegmentCommand& self) {
          const span<const uint8_t> content = self.content();
          return nb::memoryview::from_memory(content.data(), content.size());
        },
        nb::overload_cast<SegmentCommand::content_t>(&SegmentCommand::content),
        "Segment's content"_doc)

    .def_prop_rw("flags",
        nb::overload_cast<>(&SegmentCommand::flags, nb::const_),
        nb::overload_cast<uint32_t>(&SegmentCommand::flags),
        "Segment's flags"_doc)

    .def("has",
        nb::overload_cast<const Section&>(&SegmentCommand::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.MachO.Section) " belongs to the current segment"_doc,
        "section"_a)

    .def("has_section",
        nb::overload_cast<const std::string&>(&SegmentCommand::has_section, nb::const_),
        "Check if the given section name belongs to the current segment"_doc,
        "section_name"_a)

    .def("add_section",
        nb::overload_cast<const Section&>(&SegmentCommand::add_section),
        "section"_a,
        nb::rv_policy::reference_internal)

    .def("get_section",
        nb::overload_cast<const std::string&>(&SegmentCommand::get_section),
        R"delim(
        Get the :class:`~lief.MachO.Section` with the given name
        )delim"_doc, "name"_a, nb::rv_policy::reference_internal)

    LIEF_DEFAULT_STR(SegmentCommand);
  nb::class_<LinkEdit, SegmentCommand>(m, "LinkEdit");
}
}


