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
#include "pyOAT.hpp"
#include "LIEF/OAT/type_traits.hpp"

namespace LIEF {
namespace OAT {

void init_opaque_types(py::module& m) {

  py::class_<LIEF::OAT::Header::it_key_values_t::value_type>(m, "LIEF.OAT.Header.it_key_values_t.value_type")
    .def_property_readonly("key",
        [] (Header::it_key_values_t::reference p) {
          return p.first;
        }, py::return_value_policy::reference_internal)

    .def_property("value",
        [] (Header::it_key_values_t::reference p) {
         return p.second;
        },
        [] (Header::it_key_values_t::reference p, const std::string& value) {
          std::string& ref_value = p.second;
          ref_value = value;
        },
        py::return_value_policy::reference_internal);


}

}
}
