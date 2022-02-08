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
#include <sstream>
#include "pyAbstract.hpp"

#include "LIEF/Abstract/hash.hpp"

#include "LIEF/Abstract/Relocation.hpp"

namespace LIEF {
template<class T>
using getter_t = T (Relocation::*)(void) const;

template<class T>
using setter_t = void (Relocation::*)(T);

template<>
void create<Relocation>(py::module& m) {
  py::class_<Relocation, Object>(m, "Relocation",
      R"delim(
      Class which represents an abstracted Relocation
      )delim")
    .def(py::init(),
        "Default constructor")

    .def(py::init<uint64_t, uint8_t>(),
        "Constructor from an :attr:`~lief.Relocation.address` and a :attr:`~lief.Relocation.size`",
        "address"_a, "size"_a)

    .def_property("address",
        static_cast<getter_t<uint64_t>>(&Relocation::address),
        static_cast<setter_t<uint64_t>>(&Relocation::address),
        "Relocation's address")

    .def_property("size",
        static_cast<getter_t<size_t>>(&Relocation::size),
        static_cast<setter_t<size_t>>(&Relocation::size),
        "Relocation's size (in **bits**)")

    .def("__eq__", &Relocation::operator==)
    .def("__ne__", &Relocation::operator!=)
    .def("__hash__",
        [] (const Relocation& relocation) {
          return AbstractHash::hash(relocation);
        })

    .def("__str__",
        [] (const Relocation& entry)
        {
          std::ostringstream stream;
          stream << entry;
          std::string str =  stream.str();
          return str;
        });
}
}
