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
#include "pyELF.hpp"

#include "LIEF/visitors/Hash.hpp"
#include "LIEF/ELF/Relocation.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (Relocation::*)(void) const;

template<class T>
using setter_t = void (Relocation::*)(T);

void init_ELF_Relocation_class(py::module& m) {
  // Relocation object
  py::class_<Relocation>(m, "Relocation")
    .def_property("address",
        static_cast<getter_t<uint64_t>>(&Relocation::address),
        static_cast<setter_t<uint64_t>>(&Relocation::address))

    .def_property("addend",
        static_cast<getter_t<int64_t>>(&Relocation::addend),
        static_cast<setter_t<int64_t>>(&Relocation::addend))

    .def_property("type",
        static_cast<getter_t<uint32_t>>(&Relocation::type),
        static_cast<setter_t<uint32_t>>(&Relocation::type))

    .def_property_readonly("has_symbol",
        &Relocation::has_symbol)

    .def_property_readonly("symbol",
        static_cast<Symbol& (Relocation::*)(void)>(&Relocation::symbol),
        py::return_value_policy::reference_internal)

    .def_property_readonly("is_rela",
      static_cast<getter_t<bool>>(&Relocation::is_rela))

    .def_property_readonly("is_rel",
      static_cast<getter_t<bool>>(&Relocation::is_rel))


    .def("__eq__", &Relocation::operator==)
    .def("__ne__", &Relocation::operator!=)
    .def("__hash__",
        [] (const Relocation& relocation) {
          return LIEF::Hash::hash(relocation);
        })

    .def("__str__",
      [] (const Relocation& relocation)
        {
          std::ostringstream stream;
          stream << relocation;
          std::string str =  stream.str();
          return str;
        });
}
