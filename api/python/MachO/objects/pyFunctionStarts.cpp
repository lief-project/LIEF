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
#include <algorithm>

#include <string>
#include <sstream>

#include "LIEF/MachO/hash.hpp"
#include "LIEF/MachO/FunctionStarts.hpp"

#include "pyMachO.hpp"

template<class T>
using getter_t = T (FunctionStarts::*)(void) const;

template<class T>
using setter_t = void (FunctionStarts::*)(T);


void init_MachO_FunctionStarts_class(py::module& m) {

  py::class_<FunctionStarts, LoadCommand>(m, "FunctionStarts")

    .def_property("data_offset",
        static_cast<getter_t<uint32_t>>(&FunctionStarts::data_offset),
        static_cast<setter_t<uint32_t>>(&FunctionStarts::data_offset),
        "Offset in the binary where *start functions* are located")

    .def_property("data_size",
        static_cast<getter_t<uint32_t>>(&FunctionStarts::data_size),
        static_cast<setter_t<uint32_t>>(&FunctionStarts::data_size),
        "Size of the functions list in the binary")

    .def_property("functions",
        static_cast<getter_t<const std::vector<uint64_t>&>>(&FunctionStarts::functions),
        static_cast<setter_t<const std::vector<uint64_t>&>>(&FunctionStarts::functions),
        "Addresses of every function entry point in the executable\n\n"

        "This allows for functions to exist that have no entries in the symbol table.\n\n"

        ".. warning::\n\n"
        "\tThe address is relative to the ``__TEXT`` segment\n\n",
        py::return_value_policy::reference_internal)

    .def("add_function",
      &FunctionStarts::add_function,
      "Add a new function",
      "address"_a)

    .def("__eq__", &FunctionStarts::operator==)
    .def("__ne__", &FunctionStarts::operator!=)
    .def("__hash__",
        [] (const FunctionStarts& func) {
          return Hash::hash(func);
        })


    .def("__str__",
        [] (const FunctionStarts& func)
        {
          std::ostringstream stream;
          stream << func;
          std::string str = stream.str();
          return str;
        });

}
