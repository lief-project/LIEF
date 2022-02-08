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
#include "LIEF/DEX/Prototype.hpp"
#include "LIEF/DEX/hash.hpp"

#include "pyDEX.hpp"
#include "pyIterators.hpp"

namespace LIEF {
namespace DEX {

template<class T>
using getter_t = T (Prototype::*)(void) const;

template<class T>
using no_const_getter_t = T (Prototype::*)(void);

template<class T>
using setter_t = void (Prototype::*)(T);


template<>
void create<Prototype>(py::module& m) {

  init_ref_iterator<Prototype::it_params>(m, "lief.DEX.Prototype.it_params");

  py::class_<Prototype, LIEF::Object>(m, "Prototype", "DEX Prototype representation")
    .def_property_readonly("return_type",
        static_cast<no_const_getter_t<Type*>>(&Prototype::return_type),
        "" RST_CLASS_REF(lief.DEX.Type) " returned",
        py::return_value_policy::reference)

    .def_property_readonly("parameters_type",
        static_cast<no_const_getter_t<Prototype::it_params>>(&Prototype::parameters_type),
        "Iterator over parameters  " RST_CLASS_REF(lief.DEX.Type) "")

    .def("__eq__", &Prototype::operator==)
    .def("__ne__", &Prototype::operator!=)
    .def("__hash__",
        [] (const Prototype& ptype) {
          return Hash::hash(ptype);
        })

    .def("__str__",
        [] (const Prototype& ptype) {
          std::ostringstream stream;
          stream << ptype;
          return stream.str();
        });
}

}
}
