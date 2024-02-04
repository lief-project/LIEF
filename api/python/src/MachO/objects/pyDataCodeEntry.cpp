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

#include "LIEF/MachO/DataCodeEntry.hpp"
#include "LIEF/MachO/EnumToString.hpp"

#include "enums_wrapper.hpp"

#include "MachO/pyMachO.hpp"

#define PY_ENUM(x) LIEF::MachO::to_string(x), x

namespace LIEF::MachO::py {

template<>
void create<DataCodeEntry>(nb::module_& m) {
  nb::class_<DataCodeEntry, Object> cls(m, "DataCodeEntry",
      R"delim(
      Interface over an entry in the :class:`~lief.MachO.DataInCode` command
      )delim"_doc);

  enum_<DataCodeEntry::TYPES>(cls, "TYPES")
    .value(PY_ENUM(DataCodeEntry::TYPES::UNKNOWN))
    .value(PY_ENUM(DataCodeEntry::TYPES::DATA))
    .value(PY_ENUM(DataCodeEntry::TYPES::JUMP_TABLE_8))
    .value(PY_ENUM(DataCodeEntry::TYPES::JUMP_TABLE_16))
    .value(PY_ENUM(DataCodeEntry::TYPES::JUMP_TABLE_32))
    .value(PY_ENUM(DataCodeEntry::TYPES::ABS_JUMP_TABLE_32));

  cls
    // TODO(romain):
    //.def(nb::init<uint32_t, uint32_t, DataCodeEntry::TYPES>())
    .def_prop_rw("offset",
        nb::overload_cast<>(&DataCodeEntry::offset, nb::const_),
        nb::overload_cast<uint32_t>(&DataCodeEntry::offset),
        "Offset of the data"_doc)

    .def_prop_rw("length",
        nb::overload_cast<>(&DataCodeEntry::length, nb::const_),
        nb::overload_cast<uint16_t>(&DataCodeEntry::length),
        "Length of the data"_doc)

    .def_prop_rw("type",
        nb::overload_cast<>(&DataCodeEntry::type, nb::const_),
        nb::overload_cast<DataCodeEntry::TYPES>(&DataCodeEntry::type),
        "Type of the data (" RST_CLASS_REF(lief.MachO.DataCodeEntry.TYPES) ""_doc)

    LIEF_DEFAULT_STR(DataCodeEntry);



}

}
