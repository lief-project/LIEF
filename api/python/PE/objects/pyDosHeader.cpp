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
#include "LIEF/PE/DosHeader.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_abs_t = T (DosHeader::*)(void) const;

template<class T>
using setter_abs_t = void (DosHeader::*)(T);

using getter_t = getter_abs_t<uint16_t>;
using setter_t = setter_abs_t<uint16_t>;


template<>
void create<DosHeader>(py::module& m) {
  py::class_<DosHeader, LIEF::Object>(m, "DosHeader",
      R"delim(
      Class which represents the DosHeader, the **first** structure presents at the beginning of a PE file.

      Most of the attributes of this structures are not relevant, except :attr:`~lief.PE.DosHeader.addressof_new_exeheader`
      )delim")
    .def(py::init<>())
    .def_property("magic",
        static_cast<getter_t>(&DosHeader::magic),
        static_cast<setter_t>(&DosHeader::magic))

    .def_property("used_bytes_in_the_last_page",
        static_cast<getter_t>(&DosHeader::used_bytes_in_the_last_page),
        static_cast<setter_t>(&DosHeader::used_bytes_in_the_last_page))

    .def_property("file_size_in_pages",
        static_cast<getter_t>(&DosHeader::file_size_in_pages),
        static_cast<setter_t>(&DosHeader::file_size_in_pages))

    .def_property("numberof_relocation",
        static_cast<getter_t>(&DosHeader::numberof_relocation),
        static_cast<setter_t>(&DosHeader::numberof_relocation))

    .def_property("header_size_in_paragraphs",
        static_cast<getter_t>(&DosHeader::header_size_in_paragraphs),
        static_cast<setter_t>(&DosHeader::header_size_in_paragraphs))

    .def_property("minimum_extra_paragraphs",
        static_cast<getter_t>(&DosHeader::minimum_extra_paragraphs),
        static_cast<setter_t>(&DosHeader::minimum_extra_paragraphs))

    .def_property("maximum_extra_paragraphs",
        static_cast<getter_t>(&DosHeader::maximum_extra_paragraphs),
        static_cast<setter_t>(&DosHeader::maximum_extra_paragraphs))

    .def_property("initial_relative_ss",
        static_cast<getter_t>(&DosHeader::initial_relative_ss),
        static_cast<setter_t>(&DosHeader::initial_relative_ss))

    .def_property("initial_sp",
        static_cast<getter_t>(&DosHeader::initial_sp),
        static_cast<setter_t>(&DosHeader::initial_sp))

    .def_property("checksum",
        static_cast<getter_t>(&DosHeader::checksum),
        static_cast<setter_t>(&DosHeader::checksum))

    .def_property("initial_ip",
        static_cast<getter_t>(&DosHeader::initial_ip),
        static_cast<setter_t>(&DosHeader::initial_ip))

    .def_property("initial_relative_cs",
        static_cast<getter_t>(&DosHeader::initial_relative_cs),
        static_cast<setter_t>(&DosHeader::initial_relative_cs))

    .def_property("addressof_relocation_table",
        static_cast<getter_t>(&DosHeader::addressof_relocation_table),
        static_cast<setter_t>(&DosHeader::addressof_relocation_table))

    .def_property("overlay_number",
        static_cast<getter_t>(&DosHeader::overlay_number),
        static_cast<setter_t>(&DosHeader::overlay_number))

    .def_property("oem_id",
        static_cast<getter_t>(&DosHeader::oem_id),
        static_cast<setter_t>(&DosHeader::oem_id))

    .def_property("oem_info",
        static_cast<getter_t>(&DosHeader::oem_info),
        static_cast<setter_t>(&DosHeader::oem_info))

    .def_property("addressof_new_exeheader",
        static_cast<getter_abs_t<uint32_t>>(&DosHeader::addressof_new_exeheader),
        static_cast<setter_abs_t<uint32_t>>(&DosHeader::addressof_new_exeheader))


    .def("__eq__", &DosHeader::operator==)
    .def("__ne__", &DosHeader::operator!=)
    .def("__hash__",
        [] (const DosHeader& dos_header) {
          return Hash::hash(dos_header);
        })

    .def("__str__", [] (const DosHeader& header)
        {
          std::ostringstream stream;
          stream << header;
          std::string str = stream.str();
          return str;
        });

}

}
}
