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
#include "pyIterators.hpp"

#include "pyOpaqueTypes.hpp"
#include "LIEF/OAT/type_traits.hpp"


template<>
void init_ref_iterator<LIEF::OAT::Header::it_key_values_t>(py::module& m, const std::string& it_name) {

  py::class_<LIEF::OAT::Header::it_key_values_t>(m, it_name.c_str())
    .def("__getitem__",
        [] (LIEF::OAT::Header::it_key_values_t& v, size_t i) -> LIEF::OAT::Header::it_key_values_t::value_type {
            if (i >= v.size())
                throw py::index_error();
            return v[i];
        },
        py::return_value_policy::reference_internal)

    .def("__len__",
        [](LIEF::OAT::Header::it_key_values_t& v) {
          return  v.size();
        })

    .def("__iter__",
        [](LIEF::OAT::Header::it_key_values_t& v) -> LIEF::OAT::Header::it_key_values_t {
          return std::begin(v);
        }, py::return_value_policy::reference_internal)

    .def("__next__",
        [] (LIEF::OAT::Header::it_key_values_t& v) -> LIEF::OAT::Header::it_key_values_t::value_type {
          if (v == std::end(v)) {
            throw py::stop_iteration();
          }
          return *(v++);

    }, py::return_value_policy::reference_internal);

}

namespace LIEF {
namespace OAT {

void init_iterators(py::module& m) {
  init_ref_iterator<Header::it_key_values_t>(m, "Header.it_key_values_t");
  init_ref_iterator<it_methods>(m, "lief.OAT.it_methods");
  init_ref_iterator<it_classes>(m, "lief.OAT.it_classes");
  init_ref_iterator<it_dex_files>(m, "lief.OAT.it_dex_files");

}

}
}
