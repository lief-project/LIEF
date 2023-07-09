/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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
#ifndef PY_LIEF_ERROR_H
#define PY_LIEF_ERROR_H

#include <nanobind/nanobind.h>
#include "LIEF/errors.hpp"


namespace LIEF::py {
template <class Func, typename... Ts,
          std::enable_if_t<!std::is_member_pointer<std::decay_t<Func>>{}, int> = 0>
nanobind::object error_or(Func f, Ts&&... args) {
  namespace nb = nanobind;
  auto&& ret = f(std::forward<Ts>(args)...);
  if (!ret) {
    return nb::cast(as_lief_err(ret));
  }
  return nb::cast(ret.value());
}

template <class Func, typename... Ts,
          std::enable_if_t<std::is_member_pointer<std::decay_t<Func>>{}, int> = 0>
nanobind::object error_or(Func f, Ts&&... args) {
  namespace nb = nanobind;
  auto&& ret = std::mem_fn(f)(std::forward<Ts>(args)...);
  if (!ret) {
    return nb::cast(LIEF::as_lief_err(ret));
  }
  return nb::cast(ret.value());
}

void init_errors(nanobind::module_&);
}

#endif
