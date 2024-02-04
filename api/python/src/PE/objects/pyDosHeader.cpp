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

#include "LIEF/PE/DosHeader.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::py {

template<>
void create<DosHeader>(nb::module_& m) {
  nb::class_<DosHeader, LIEF::Object>(m, "DosHeader",
      R"delim(
      Class which represents the DosHeader, the **first** structure presents at the beginning of a PE file.

      Most of the attributes of this structures are not relevant, except :attr:`~lief.PE.DosHeader.addressof_new_exeheader`
      )delim"_doc)
    .def_static("create", &DosHeader::create, nb::rv_policy::move)

    .def_prop_rw("magic",
        nb::overload_cast<>(&DosHeader::magic, nb::const_),
        nb::overload_cast<uint16_t>(&DosHeader::magic))

    .def_prop_rw("used_bytes_in_last_page",
        nb::overload_cast<>(&DosHeader::used_bytes_in_last_page, nb::const_),
        nb::overload_cast<uint16_t>(&DosHeader::used_bytes_in_last_page))

    .def_prop_rw("file_size_in_pages",
        nb::overload_cast<>(&DosHeader::file_size_in_pages, nb::const_),
        nb::overload_cast<uint16_t>(&DosHeader::file_size_in_pages))

    .def_prop_rw("numberof_relocation",
        nb::overload_cast<>(&DosHeader::numberof_relocation, nb::const_),
        nb::overload_cast<uint16_t>(&DosHeader::numberof_relocation))

    .def_prop_rw("header_size_in_paragraphs",
        nb::overload_cast<>(&DosHeader::header_size_in_paragraphs, nb::const_),
        nb::overload_cast<uint16_t>(&DosHeader::header_size_in_paragraphs))

    .def_prop_rw("minimum_extra_paragraphs",
        nb::overload_cast<>(&DosHeader::minimum_extra_paragraphs, nb::const_),
        nb::overload_cast<uint16_t>(&DosHeader::minimum_extra_paragraphs))

    .def_prop_rw("maximum_extra_paragraphs",
        nb::overload_cast<>(&DosHeader::maximum_extra_paragraphs, nb::const_),
        nb::overload_cast<uint16_t>(&DosHeader::maximum_extra_paragraphs))

    .def_prop_rw("initial_relative_ss",
        nb::overload_cast<>(&DosHeader::initial_relative_ss, nb::const_),
        nb::overload_cast<uint16_t>(&DosHeader::initial_relative_ss))

    .def_prop_rw("initial_sp",
        nb::overload_cast<>(&DosHeader::initial_sp, nb::const_),
        nb::overload_cast<uint16_t>(&DosHeader::initial_sp))

    .def_prop_rw("checksum",
        nb::overload_cast<>(&DosHeader::checksum, nb::const_),
        nb::overload_cast<uint16_t>(&DosHeader::checksum))

    .def_prop_rw("initial_ip",
        nb::overload_cast<>(&DosHeader::initial_ip, nb::const_),
        nb::overload_cast<uint16_t>(&DosHeader::initial_ip))

    .def_prop_rw("initial_relative_cs",
        nb::overload_cast<>(&DosHeader::initial_relative_cs, nb::const_),
        nb::overload_cast<uint16_t>(&DosHeader::initial_relative_cs))

    .def_prop_rw("addressof_relocation_table",
        nb::overload_cast<>(&DosHeader::addressof_relocation_table, nb::const_),
        nb::overload_cast<uint16_t>(&DosHeader::addressof_relocation_table))

    .def_prop_rw("overlay_number",
        nb::overload_cast<>(&DosHeader::overlay_number, nb::const_),
        nb::overload_cast<uint16_t>(&DosHeader::overlay_number))

    .def_prop_rw("oem_id",
        nb::overload_cast<>(&DosHeader::oem_id, nb::const_),
        nb::overload_cast<uint16_t>(&DosHeader::oem_id))

    .def_prop_rw("oem_info",
        nb::overload_cast<>(&DosHeader::oem_info, nb::const_),
        nb::overload_cast<uint16_t>(&DosHeader::oem_info))

    .def_prop_rw("addressof_new_exeheader",
        nb::overload_cast<>(&DosHeader::addressof_new_exeheader, nb::const_),
        nb::overload_cast<uint32_t>(&DosHeader::addressof_new_exeheader))

    LIEF_COPYABLE(DosHeader)
    LIEF_DEFAULT_STR(DosHeader);
}

}
