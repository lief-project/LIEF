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
#include "LIEF/MachO/DataCodeEntry.hpp"
#include "LIEF/MachO/EnumToString.hpp"

#include "enums_wrapper.hpp"

#include "pyMachO.hpp"

#define PY_ENUM(x) LIEF::MachO::to_string(x), x

namespace LIEF {
namespace MachO {

template<class T>
using getter_t = T (DataCodeEntry::*)(void) const;

template<class T>
using setter_t = void (DataCodeEntry::*)(T);


template<>
void create<DataCodeEntry>(py::module& m) {


  py::class_<DataCodeEntry, LIEF::Object> cls(m, "DataCodeEntry",
      R"delim(
      Interface over an entry in the :class:`~lief.MachO.DataInCode` command
      )delim");

  cls
    .def(py::init<uint32_t, uint32_t, DataCodeEntry::TYPES>())
    .def_property("offset",
        static_cast<getter_t<uint32_t>>(&DataCodeEntry::offset),
        static_cast<setter_t<uint32_t>>(&DataCodeEntry::offset),
        "Offset of the data")

    .def_property("length",
        static_cast<getter_t<uint16_t>>(&DataCodeEntry::length),
        static_cast<setter_t<uint16_t>>(&DataCodeEntry::length),
        "Length of the data")

    .def_property("type",
        static_cast<getter_t<DataCodeEntry::TYPES>>(&DataCodeEntry::type),
        static_cast<setter_t<DataCodeEntry::TYPES>>(&DataCodeEntry::type),
        "Type of the data (" RST_CLASS_REF(lief.MachO.DataCodeEntry.TYPES) "")


    .def("__eq__", &DataCodeEntry::operator==)
    .def("__ne__", &DataCodeEntry::operator!=)
    .def("__hash__",
        [] (const DataCodeEntry& func) {
          return Hash::hash(func);
        })


    .def("__str__",
        [] (const DataCodeEntry& func)
        {
          std::ostringstream stream;
          stream << func;
          std::string str = stream.str();
          return str;
        });


  LIEF::enum_<DataCodeEntry::TYPES>(cls, "TYPES")
    .value(PY_ENUM(DataCodeEntry::TYPES::UNKNOWN))
    .value(PY_ENUM(DataCodeEntry::TYPES::DATA))
    .value(PY_ENUM(DataCodeEntry::TYPES::JUMP_TABLE_8))
    .value(PY_ENUM(DataCodeEntry::TYPES::JUMP_TABLE_16))
    .value(PY_ENUM(DataCodeEntry::TYPES::JUMP_TABLE_32))
    .value(PY_ENUM(DataCodeEntry::TYPES::ABS_JUMP_TABLE_32));

}

}
}
