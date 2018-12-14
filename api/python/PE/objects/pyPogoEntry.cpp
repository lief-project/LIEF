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
#include "LIEF/PE/PogoEntry.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (PogoEntry::*)(void) const;

template<class T>
using setter_t = void (PogoEntry::*)(T);


template<>
void create<PogoEntry>(py::module& m) {
  py::class_<PogoEntry, LIEF::Object>(m, "PogoEntry")
    .def(py::init<>())

    .def_property("name",
        [] (const PogoEntry& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<const std::string&>>(&PogoEntry::name))

    .def_property("start_rva",
        static_cast<getter_t<uint32_t>>(&PogoEntry::start_rva),
        static_cast<setter_t<uint32_t>>(&PogoEntry::start_rva))

    .def_property("size",
        static_cast<getter_t<uint32_t>>(&PogoEntry::size),
        static_cast<setter_t<uint32_t>>(&PogoEntry::size))


    .def("__eq__", &PogoEntry::operator==)
    .def("__ne__", &PogoEntry::operator!=)
    .def("__hash__",
        [] (const PogoEntry& pogo_entry) {
          return Hash::hash(pogo_entry);
        })

    .def("__str__", [] (const PogoEntry& entry)
        {
          std::ostringstream stream;
          stream << entry;
          std::string str = stream.str();
          return str;
        });
}
}
}
