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
#include "init.hpp"

#include "LIEF/Abstract/hash.hpp"

#include "LIEF/Abstract/Relocation.hpp"

template<class T>
using getter_t = T (LIEF::Relocation::*)(void) const;

template<class T>
using setter_t = void (LIEF::Relocation::*)(T);

void init_LIEF_Relocation_class(py::module& m) {
  py::class_<LIEF::Relocation, LIEF::Object>(m, "Relocation")
    .def(py::init(),
        "Default constructor")

    .def(py::init<uint64_t, uint8_t>(),
        "Constructor from :attr:`~lief.Relocation.address` and :attr:`~lief.Relocation.size`",
        "address"_a, "size"_a)

    .def_property("address",
        static_cast<getter_t<uint64_t>>(&LIEF::Relocation::address),
        static_cast<setter_t<uint64_t>>(&LIEF::Relocation::address),
        "Relocation's address")

    .def_property("size",
        static_cast<getter_t<size_t>>(&LIEF::Relocation::size),
        static_cast<setter_t<size_t>>(&LIEF::Relocation::size),
        "Relocation's size (in **bits**)")

    .def("__eq__", &LIEF::Relocation::operator==)
    .def("__ne__", &LIEF::Relocation::operator!=)
    .def("__hash__",
        [] (const LIEF::Relocation& relocation) {
          return LIEF::AbstractHash::hash(relocation);
        })

    .def("__str__",
        [] (const LIEF::Relocation& entry)
        {
          std::ostringstream stream;
          stream << entry;
          std::string str =  stream.str();
          return str;
        });


}
