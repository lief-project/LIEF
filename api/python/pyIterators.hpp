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
#ifndef PY_LIEF_ITERATORS_H_
#define PY_LIEF_ITERATORS_H_
#include <pybind11/pybind11.h>


#include "LIEF/LIEF.hpp"
#include "LIEF/Abstract/type_traits.hpp"
#include "LIEF/ELF/type_traits.hpp"
#include "LIEF/PE/type_traits.hpp"
#include "LIEF/MachO/type_traits.hpp"


namespace py = pybind11;


void init_LIEF_iterators(py::module&);

template<class T>
void init_ref_iterator(py::module& m, const std::string& it_name = typeid(T).name()) {
  py::class_<T>(m, it_name.c_str())
    .def("__getitem__",
        [](T& v, size_t i) -> typename T::reference {
            if (i >= v.size())
                throw py::index_error();
            return v[i];
        },
        py::return_value_policy::reference)

    .def("__len__",
        [](T& v) {
          return  v.size();
        })

    .def("__iter__",
        [](T& v) -> T {
          return std::begin(v);
        }, py::return_value_policy::reference_internal)

    .def("__next__",
        [] (T& v) -> typename T::reference {
          if (v == std::end(v)) {
            throw py::stop_iteration();
          }
          return *(v++);

    }, py::return_value_policy::reference);



}

#endif
