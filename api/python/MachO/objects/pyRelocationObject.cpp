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
#include "LIEF/MachO/RelocationObject.hpp"

#include "pyMachO.hpp"

template<class T>
using getter_t = T (RelocationObject::*)(void) const;

template<class T>
using setter_t = void (RelocationObject::*)(T);


void init_MachO_RelocationObject_class(py::module& m) {

  py::class_<RelocationObject, Relocation>(m, "RelocationObject")

    .def_property("value",
        static_cast<getter_t<int32_t>>(&RelocationObject::value),
        static_cast<setter_t<int32_t>>(&RelocationObject::value),
        "For **scattered** relocations, the address of the relocatable expression "
        "for the item in the file that needs to be updated if the address is changed.\n\n"

        "For relocatable expressions with the difference of two section addresses, "
        "the address from which to subtract (in mathematical terms, the minuend) "
        "is contained in the first relocation entry and the address to subtract (the subtrahend) "
        "is contained in the second relocation entry.",
        py::return_value_policy::reference_internal)


    .def_property_readonly("is_scattered",
        &RelocationObject::is_scattered,
        "``True`` if the relocation is a scattered one")

    .def("__eq__", &RelocationObject::operator==)
    .def("__ne__", &RelocationObject::operator!=)
    .def("__hash__",
        [] (const RelocationObject& relocation) {
          return Hash::hash(relocation);
        })


    .def("__str__",
        [] (const RelocationObject& relocation)
        {
          std::ostringstream stream;
          stream << relocation;
          std::string str = stream.str();
          return str;
        });

}
