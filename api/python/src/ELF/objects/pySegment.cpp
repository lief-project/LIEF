/* opyright 2017 - 2023 R. Thomas
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
#include <string>
#include <sstream>
#include <vector>

#include <nanobind/operators.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include "LIEF/ELF/Segment.hpp"
#include "LIEF/ELF/Section.hpp"

#include "ELF/pyELF.hpp"
#include "pyErr.hpp"
#include "pyIterator.hpp"
#include "nanobind/extra/memoryview.hpp"

#include "enums_wrapper.hpp"

namespace LIEF::ELF::py {

template<>
void create<Segment>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Segment, LIEF::Object> seg(m, "Segment",
    R"delim(
    Class which represents the ELF segments
    )delim"_doc
  );

  init_ref_iterator<Segment::it_sections>(seg, "it_sections");

  #define ENTRY(X) .value(to_string(Segment::TYPE::X), Segment::TYPE::X)
  enum_<Segment::TYPE>(seg, "TYPE")
    ENTRY(PT_NULL)
    ENTRY(LOAD)
    ENTRY(DYNAMIC)
    ENTRY(INTERP)
    ENTRY(NOTE)
    ENTRY(SHLIB)
    ENTRY(PHDR)
    ENTRY(TLS)
    ENTRY(GNU_EH_FRAME)
    ENTRY(GNU_STACK)
    ENTRY(GNU_PROPERTY)
    ENTRY(GNU_RELRO)
    ENTRY(ARM_ARCHEXT)
    ENTRY(ARM_EXIDX)
    ENTRY(AARCH64_MEMTAG_MTE)
    ENTRY(MIPS_REGINFO)
    ENTRY(MIPS_RTPROC)
    ENTRY(MIPS_OPTIONS)
    ENTRY(MIPS_ABIFLAGS)
    ENTRY(RISCV_ATTRIBUTES)
  ;
  #undef ENTRY

  #define ENTRY(X) .value(to_string(Segment::FLAGS::X), Segment::FLAGS::X)
  enum_<Segment::FLAGS>(seg, "FLAGS", nb::is_arithmetic())
    ENTRY(R)
    ENTRY(W)
    ENTRY(X)
    ENTRY(NONE)
  ;
  #undef ENTRY

  seg
    .def(nb::init<>())
    .def_static("from_raw",
        [] (nb::bytes raw) {
          const std::vector<uint8_t>& cpp_raw = {raw.c_str(), raw.c_str() + raw.size()};
          auto* f_ptr = nb::overload_cast<const std::vector<uint8_t>&>(&Segment::from_raw);
          return error_or(f_ptr, cpp_raw);
        })

    .def_prop_rw("type",
        nb::overload_cast<>(&Segment::type, nb::const_),
        nb::overload_cast<Segment::TYPE>(&Segment::type),
        "Segment's type"_doc)

    .def_prop_rw("flags",
        nb::overload_cast<>(&Segment::flags, nb::const_),
        nb::overload_cast<Segment::FLAGS>(&Segment::flags),
        "The flag permissions associated with this segment"_doc)

    .def_prop_rw("file_offset",
        nb::overload_cast<>(&Segment::file_offset, nb::const_),
        nb::overload_cast<uint64_t>(&Segment::file_offset),
        "The file offset of the data associated with this segment"_doc)

    .def_prop_rw("virtual_address",
        nb::overload_cast<>(&Segment::virtual_address, nb::const_),
        nb::overload_cast<uint64_t>(&Segment::virtual_address),
        R"delim(
        The virtual address of the segment.

        .. warning::
            The ELF format specifications require the following relationship:

            .. math::
                \text{virtual address} \equiv \text{file offset} \pmod{\text{page size}}
                \text{virtual address} \equiv \text{file offset} \pmod{\text{alignment}}
        )delim"_doc)

    .def_prop_rw("physical_address",
        nb::overload_cast<>(&Segment::physical_address, nb::const_),
        nb::overload_cast<uint64_t>(&Segment::physical_address),
        R"delim(
        The physical address of the segment. This value is not really relevant
        on systems like Linux or Android. On the other hand, Qualcomm trustlets
        might use this value.

        Usually this value matches :attr:`~lief.ELF.Segment.virtual_address`
        )delim"_doc)

    .def_prop_rw("physical_size",
        nb::overload_cast<>(&Segment::physical_size, nb::const_),
        nb::overload_cast<uint64_t>(&Segment::physical_size),
        "The **file** size of the data associated with this segment"_doc)

    .def_prop_rw("virtual_size",
        nb::overload_cast<>(&Segment::virtual_size, nb::const_),
        nb::overload_cast<uint64_t>(&Segment::virtual_size),
        R"delim(
        The in-memory size of this segment.

        Usually, if the ``.bss`` segment is wrapped by this segment
        then, virtual_size is larger than physical_size
        )delim"_doc)

    .def_prop_rw("alignment",
        nb::overload_cast<>(&Segment::alignment, nb::const_),
        nb::overload_cast<uint64_t>(&Segment::alignment),
        "The offset alignment of the segment"_doc)

    .def_prop_rw("content",
        [] (const Segment& self) {
          const span<const uint8_t> content = self.content();
          return nb::memoryview::from_memory(content.data(), content.size());
        },
        nb::overload_cast<std::vector<uint8_t>>(&Segment::content),
        "The raw data associated with this segment."_doc)

    .def("add", &Segment::add,
        "Add the given flag to the list of :attr:`~lief.ELF.Segment.flags`"_doc,
        "flag"_a)

    .def("remove", &Segment::remove,
        "Remove the given flag from the list of :attr:`~lief.ELF.Segment.flags`"_doc,
        "flag"_a)

    .def("has",
        nb::overload_cast<Segment::FLAGS>(&Segment::has, nb::const_),
        "Check if the given flag is present"_doc,
        "flag"_a)

    .def("has",
        nb::overload_cast<const Section&>(&Segment::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.ELF.Section) " is present "
        "in :attr:`~lief.ELF.Segment.sections`"_doc,
        "section"_a)

    .def("has",
        nb::overload_cast<const std::string&>(&Segment::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.ELF.Section) " 's name is present "
        "in :attr:`~lief.ELF.Segment.sections`"_doc,
        "section_name"_a)

    .def_prop_ro("sections",
      nb::overload_cast<>(&Segment::sections),
      "Iterator over the " RST_CLASS_REF(lief.ELF.Section) " wrapped by this segment"_doc,
      nb::keep_alive<0, 1>())

    .def(nb::self += Segment::FLAGS())
    .def(nb::self -= Segment::FLAGS())

    .def("__contains__",
        nb::overload_cast<Segment::FLAGS>(&Segment::has, nb::const_),
        "Check if the given flag is present"_doc)

    .def("__contains__",
        nb::overload_cast<const Section&>(&Segment::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.ELF.Section) " is present "
        "in :attr:`~lief.ELF.Segment.sections`"_doc)

    .def("__contains__",
        nb::overload_cast<const std::string&>(&Segment::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.ELF.Section) " 's name is present "
        "in :attr:`~lief.ELF.Segment.sections`"_doc)

    LIEF_DEFAULT_STR(Segment);

}

}
