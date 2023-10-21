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

#include "typing.hpp"

namespace LIEF::py {

template<class RetTy>
struct typing_error {
  using value_type = typename RetTy::value_type;
  using err_type = typename RetTy::error_type;
  LIEF_PY_DEFAULT_CTOR(typing_error, nanobind::object);
  LIEF_PY_DEFAULT_WRAPPER(typing_error);
};
}

NAMESPACE_BEGIN(NB_NAMESPACE)
NAMESPACE_BEGIN(detail)
template<class T>
struct type_caster<LIEF::py::typing_error<T>> {
  using typing_type = typename LIEF::py::typing_error<T>;
  NB_TYPE_CASTER(LIEF::py::typing_error<T>,
      const_name("Union[") +
                 make_caster<typename typing_type::value_type>::Name +
      const_name(", ") +
                 make_caster<typename typing_type::err_type>::Name +
      const_name("]"));

  bool from_python(handle src, uint8_t, cleanup_list *) noexcept {
    return false;
  }
  static handle from_cpp(const LIEF::py::typing_error<T> &value, rv_policy,
                         cleanup_list *) noexcept {
    return value.obj;
  }
};
NAMESPACE_END(detail)
NAMESPACE_END(NB_NAMESPACE)

namespace LIEF::py {
template <class Func, typename... Ts,
          class RetTy = std::invoke_result_t<Func, Ts...>,
          std::enable_if_t<!std::is_member_pointer<std::decay_t<Func>>{}, int> = 0>
typing_error<RetTy> error_or(Func f, Ts&&... args) {
  namespace nb = nanobind;
  auto&& ret = f(std::forward<Ts>(args)...);
  if (!ret) {
    return nb::cast(as_lief_err(ret));
  }
  return nb::cast(ret.value());
}

template <class Func, typename... Ts,
          class RetTy = std::invoke_result_t<Func, Ts...>,
          std::enable_if_t<std::is_member_pointer<std::decay_t<Func>>{}, int> = 0>
typing_error<RetTy> error_or(Func f, Ts&&... args) {
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
