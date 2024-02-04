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
#include <algorithm>

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

#include "LIEF/MachO/DataInCode.hpp"

#include "pyIterator.hpp"
#include "MachO/pyMachO.hpp"

#include "nanobind/extra/memoryview.hpp"

namespace LIEF::MachO::py {

template<>
void create<DataInCode>(nb::module_& m) {
  using namespace LIEF::py;

  init_ref_iterator<DataInCode::it_entries>(m, "it_data_in_code_entries");

  nb::class_<DataInCode, LoadCommand>(m, "DataInCode",
      R"delim(
      Interface of the LC_DATA_IN_CODE command

      This command is used to list slices of code sections that contain data. The *slices*
      information are stored as an array of :class:`~lief.MachO.DataCodeEntry`
      )delim"_doc)

    .def_prop_rw("data_offset",
        nb::overload_cast<>(&DataInCode::data_offset, nb::const_),
        nb::overload_cast<uint32_t>(&DataInCode::data_offset),
        "Start of the array of the DataCodeEntry entries"_doc)

    .def_prop_rw("data_size",
        nb::overload_cast<>(&DataInCode::data_size, nb::const_),
        nb::overload_cast<uint32_t>(&DataInCode::data_size),
        "Whole size of the array (``size = sizeof(DataCodeEntry) * nb_elements``)"_doc)

    .def_prop_ro("entries",
        nb::overload_cast<>(&DataInCode::entries),
        "Iterator over " RST_CLASS_REF(lief.MachO.DataCodeEntry) ""_doc,
        nb::rv_policy::reference_internal)

    .def("add", &DataInCode::add,
        "Add an new " RST_CLASS_REF(lief.MachO.DataCodeEntry) ""_doc,
        "entry"_a)

    .def_prop_ro("content",
        [] (const DataInCode& self) {
          const span<const uint8_t> content = self.content();
          return nb::memoryview::from_memory(content.data(), content.size());
        }, "The original content as a bytes stream"_doc)

  LIEF_DEFAULT_STR(DataInCode);


}
}
