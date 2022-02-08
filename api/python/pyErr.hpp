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
#ifndef PY_LIEF_ERR_H_
#define PY_LIEF_ERR_H_
#include <pybind11/pybind11.h>
#include "LIEF/errors.hpp"

namespace py = pybind11;


template <class Func, typename... Ts,
          std::enable_if_t<!std::is_member_pointer<std::decay_t<Func>>{}, int> = 0>
py::object error_or(Func f, Ts&&... args) {
  auto&& ret = f(std::forward<Ts>(args)...);
  if (!ret) {
    return py::cast(LIEF::as_lief_err(ret));
  }
  return py::cast(ret.value());
}


template <class Func, typename... Ts,
          std::enable_if_t<std::is_member_pointer<std::decay_t<Func>>{}, int> = 0>
py::object error_or(Func f, Ts&&... args) {
  auto&& ret = std::mem_fn(f)(std::forward<Ts>(args)...);
  if (!ret) {
    return py::cast(LIEF::as_lief_err(ret));
  }
  return py::cast(ret.value());
}


void init_LIEF_errors(py::module&);

#endif
