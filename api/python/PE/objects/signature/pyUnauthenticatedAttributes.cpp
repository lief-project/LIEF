/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 * Copyright 2020 K. Nakagawa
 *
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

#include "LIEF/PE/signature/UnauthenticatedAttributes.hpp"

#include "pyPE.hpp"

namespace LIEF {
namespace PE {

template<class T>
using getter_t = T (UnauthenticatedAttributes::*)(void) const;

template<class T>
using setter_t = void (UnauthenticatedAttributes::*)(T);


template<>
void create<UnauthenticatedAttributes>(py::module& m) {

  py::class_<UnauthenticatedAttributes, LIEF::Object>(m, "UnauthenticatedAttributes")

    .def_property_readonly("nested_signature",
        &UnauthenticatedAttributes::nested_signature,
        "Return nested signature")

    .def_property_readonly("counter_signature",
        &UnauthenticatedAttributes::counter_signature,
        "Return counter signature")

    .def_property_readonly("timestamping_signature",
        &UnauthenticatedAttributes::timestamping_signature,
        "return")

    .def("__str__",
        [] (const UnauthenticatedAttributes& unauth_attributes)
        {
          std::ostringstream stream;
          stream << unauth_attributes;
          return stream.str();
        });
}

}
}