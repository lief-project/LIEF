/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#ifndef PY_LIEF_ITERATORS_H
#define PY_LIEF_ITERATORS_H

#include "nanobind/nanobind.h"
#include "nanobind/make_iterator.h"

#include <string>

namespace nb = nanobind;

namespace LIEF::py {

template<class T>
void init_ref_iterator(nanobind::handle& m, const char* it_name) {
  using ElementTy = typename T::value_type;

  if (auto type = nb::type<T>(); type.is_valid()) {
    m.attr(it_name) = type;
    return;
  }

  nb::class_<T>(m, it_name)
    .def_prop_ro_static("__doc__",
        [] (const nb::object&) -> std::string {
          using namespace std::literals;
          if (auto type = nb::type<ElementTy>(); type.is_valid()) {
            nb::str name = nb::type_name(type);
            return "Iterator over :class:`"s + name.c_str() + "`";
          }
          return "";
        })

    .def("__getitem__",
        [] (T& v, Py_ssize_t i) -> typename T::reference {
          const size_t size = v.size();
          if (i < 0) {
            i += static_cast<Py_ssize_t>(size);
          }
          if (i < 0 || static_cast<size_t>(i) >= size) {
            throw nb::index_error();
          }
          return v[i];
        },
        nb::rv_policy::reference_internal)

    .def("__len__",
        [] (T& v) {
          return v.size();
        })

    .def("__iter__",
        [] (const T& v) {
          return v;
        }, nb::rv_policy::reference_internal)

    .def("__next__",
        [] (T& v) -> typename T::reference {
          if (v == std::end(v)) {
            throw nb::stop_iteration();
          }
          auto& value = *v;
          ++v;
          return value;
        }, nb::rv_policy::reference_internal);
}
}

#endif
