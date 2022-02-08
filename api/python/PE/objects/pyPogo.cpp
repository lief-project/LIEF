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
#include "pyPE.hpp"
#include "pyIterators.hpp"

#include "LIEF/PE/hash.hpp"
#include "LIEF/PE/Pogo.hpp"

#include <string>
#include <sstream>

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (Pogo::*)(void) const;

template<class T>
using setter_t = void (Pogo::*)(T);

template<class T>
using no_const_getter = T (Pogo::*)(void);

template<>
void create<Pogo>(py::module& m) {
  py::class_<Pogo, LIEF::Object> pogo(m, "Pogo");

  init_ref_iterator<Pogo::it_entries>(pogo, "it_entries");

  pogo
    .def(py::init<>())

    .def_property_readonly("entries",
        static_cast<no_const_getter<Pogo::it_entries>>(&Pogo::entries),
        py::return_value_policy::reference_internal)

    .def_property_readonly("signature",
        static_cast<getter_t<POGO_SIGNATURES>>(&Pogo::signature),
        "Type of the pogo (" RST_CLASS_REF(lief.PE.POGO_SIGNATURES) ")")


    .def("__eq__", &Pogo::operator==)
    .def("__ne__", &Pogo::operator!=)
    .def("__hash__",
        [] (const Pogo& pogo_entry) {
          return Hash::hash(pogo_entry);
        })

    .def("__str__", [] (const Pogo& entry)
        {
          std::ostringstream stream;
          stream << entry;
          std::string str = stream.str();
          return str;
        });
}
}
}
