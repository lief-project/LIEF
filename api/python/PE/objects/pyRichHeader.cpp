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

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/RichHeader.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (RichHeader::*)(void) const;

template<class T>
using setter_t = void (RichHeader::*)(T);

template<class T>
using no_const_getter = T (RichHeader::*)(void);

void init_PE_RichHeader_class(py::module& m) {
  py::class_<RichHeader>(m, "RichHeader")
    .def(py::init<>())
    .def_property("key",
        static_cast<getter_t<uint32_t>>(&RichHeader::key),
        static_cast<setter_t<uint32_t>>(&RichHeader::key),
        "Key used to encode the header (xor operation)")

    .def_property_readonly("entries",
        static_cast<no_const_getter<it_rich_entries>>(&RichHeader::entries),
        "Return binary's " RST_CLASS_REF(lief.PE.RichEntry) " within the header",
        py::return_value_policy::reference)

    .def("add_entry",
        static_cast<void (RichHeader::*)(const RichEntry&)>(&RichHeader::add_entry),
        "Add a new " RST_CLASS_REF(lief.PE.RichEntry) "",
        "entry"_a)

    .def("add_entry",
        static_cast<void (RichHeader::*)(uint16_t, uint16_t, uint32_t)>(&RichHeader::add_entry),
        "Add a new " RST_CLASS_REF(lief.PE.RichEntry) " given its "
        ":attr:`~lief.PE.RichEntry.id`, "
        ":attr:`~lief.PE.RichEntry.build_id`, "
        ":attr:`~lief.PE.RichEntry.count`",
        "id"_a, "build_id"_a, "count"_a)

    .def("__eq__", &RichHeader::operator==)
    .def("__ne__", &RichHeader::operator!=)
    .def("__hash__",
        [] (const RichHeader& rich_header) {
          return Hash::hash(rich_header);
        })

    .def("__str__", [] (const RichHeader& rich_header)
        {
          std::ostringstream stream;
          stream << rich_header;
          std::string str = stream.str();
          return str;
        });



}
