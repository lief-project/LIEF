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
#ifndef PY_LIEF_ITERATORS_H_
#define PY_LIEF_ITERATORS_H_
#include <pybind11/pybind11.h>

#include "LIEF/LIEF.hpp"

namespace py = pybind11;

template<class T>
void init_ref_iterator(py::handle& m, const char* it_name) {
  py::class_<T>(m, it_name)
    .def("__getitem__",
        [](T& v, size_t i) -> typename T::reference {
            if (i >= v.size())
                throw py::index_error();
            return v[i];
        },
        py::return_value_policy::reference_internal, py::keep_alive<1, 0>())

    .def("__len__",
        [] (T& v) {
          return  v.size();
        })

    .def("__iter__",
        [] (const T& v) {
          return py::make_iterator(std::begin(v), std::end(v));
        }, py::keep_alive<0, 1>())

    .def("__next__",
        [] (T& v) -> typename T::reference {
          if (v == std::end(v)) {
            throw py::stop_iteration();
          }
          return *(v++);
        }, py::return_value_policy::reference_internal, py::keep_alive<1, 0>());



}

#endif
