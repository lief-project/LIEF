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
#include <algorithm>

#include <string>
#include <sstream>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/DataInCode.hpp"

#include "pyIterators.hpp"
#include "pyMachO.hpp"


namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (DataInCode::*)(void) const;

template<class T>
using setter_t = void (DataInCode::*)(T);


template<>
void create<DataInCode>(py::module& m) {

  // Init Iterator
  init_ref_iterator<DataInCode::it_entries>(m, "it_data_in_code_entries");

  py::class_<DataInCode, LoadCommand>(m, "DataInCode",
      R"delim(
      Interface of the LC_DATA_IN_CODE command

      This command is used to list slices of code sections that contain data. The *slices*
      information are stored as an array of :class:`~lief.MachO.DataCodeEntry`
      )delim")
    .def_property("data_offset",
        static_cast<getter_t<uint32_t>>(&DataInCode::data_offset),
        static_cast<setter_t<uint32_t>>(&DataInCode::data_offset),
        "Start of the array of the DataCodeEntry entries")

    .def_property("data_size",
        static_cast<getter_t<uint32_t>>(&DataInCode::data_size),
        static_cast<setter_t<uint32_t>>(&DataInCode::data_size),
        "Whole size of the array (``size = sizeof(DataCodeEntry) * nb_elements``)")

    .def_property_readonly("entries",
        static_cast<DataInCode::it_entries (DataInCode::*)(void)>(&DataInCode::entries),
        "Iterator over " RST_CLASS_REF(lief.MachO.DataCodeEntry) "",
        py::return_value_policy::reference_internal)

    .def("add",
        &DataInCode::add,
        "Add an new " RST_CLASS_REF(lief.MachO.DataCodeEntry) "",
        "entry"_a)

    .def_property_readonly("content",
        [] (const DataInCode& self) {
          span<const uint8_t> content = self.content();
          return py::memoryview::from_memory(content.data(), content.size());
        }, "The original content as a bytes stream")


    .def("__eq__", &DataInCode::operator==)
    .def("__ne__", &DataInCode::operator!=)
    .def("__hash__",
        [] (const DataInCode& func) {
          return Hash::hash(func);
        })


    .def("__str__",
        [] (const DataInCode& func)
        {
          std::ostringstream stream;
          stream << func;
          std::string str = stream.str();
          return str;
        });

}
}
}
