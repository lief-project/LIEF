/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
 * Copyright 2017 - 2021 K. Nakagawa
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
#include "LIEF/PE/resources/ResourceAccelerator.hpp"

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (ResourceAccelerator::*)(void) const;

template<class T>
using setter_t = void (ResourceAccelerator::*)(T);


template<>
void create<ResourceAccelerator>(py::module& m) {
  py::class_<ResourceAccelerator, LIEF::Object>(m, "ResourceAccelerator")

    .def_property_readonly("flags",
      static_cast<getter_t<int16_t>>(&ResourceAccelerator::flags),
      "Describe the keyboard accelerator characteristics.")

    .def_property_readonly("ansi",
      static_cast<getter_t<int16_t>>(&ResourceAccelerator::ansi),
      "An ANSI character value or a virtual-key code that identifies the accelerator key.")

    .def_property_readonly("id",
      static_cast<getter_t<uint16_t>>(&ResourceAccelerator::id),
      "An identifier for the keyboard accelerator.")

    .def_property_readonly("padding",
      static_cast<getter_t<int16_t>>(&ResourceAccelerator::padding),
      "The number of bytes inserted to ensure that the structure is aligned on a DWORD boundary.")

    .def("__eq__", &ResourceAccelerator::operator==)
    .def("__ne__", &ResourceAccelerator::operator!=)
    .def("__hash__",
      [] (const ResourceAccelerator& acc) {
        return Hash::hash(acc);
      })

    .def("__str__",
      [] (const ResourceAccelerator& acc) {
        std::ostringstream stream;
        stream << acc;
        return stream.str();
      });
}
}
}
