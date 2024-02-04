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
#ifndef PY_LIEF_ERROR_H
#define PY_LIEF_ERROR_H

#include <nanobind/nanobind.h>
#include "LIEF/errors.hpp"

#include "typing.hpp"

namespace LIEF::py {
template<class RetTy>
struct typing_error : public nanobind::object {
  using value_type = typename RetTy::value_type;
  using err_type = typename RetTy::error_type;

  static constexpr auto Name = nanobind::detail::const_name("Union[") +
                 nanobind::detail::make_caster<value_type>::Name +
      nanobind::detail::const_name(", ") +
                 nanobind::detail::make_caster<err_type>::Name +
      nanobind::detail::const_name("]");

  LIEF_PY_DEFAULT_CTOR(typing_error, nanobind::object);
  NB_OBJECT_DEFAULT_NONAME(typing_error, object, check)

  static bool check(handle h) {
    return true;
  }
};

template<class RetTy>
struct value_or_none_t : public nanobind::object {
  LIEF_PY_DEFAULT_CTOR(value_or_none_t, nanobind::object);
  using value_type = typename RetTy::value_type;

  static constexpr auto Name = nanobind::detail::const_name("Optional[") +
                 nanobind::detail::make_caster<value_type>::Name +
      nanobind::detail::const_name("]");

  NB_OBJECT_DEFAULT_NONAME(value_or_none_t, object, check)
  static bool check(handle h) {
    return true;
  }
};


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


template <class Func, typename... Ts,
          class RetTy = std::invoke_result_t<Func, Ts...> >
value_or_none_t<RetTy> value_or_none(Func f, Ts&&... args) {
  namespace nb = nanobind;
  if constexpr (std::is_member_pointer_v<std::decay_t<Func>>) {
    auto&& ret = std::mem_fn(f)(std::forward<Ts>(args)...);
    if (!ret) {
      return nb::none();
    }
    return nb::cast(*ret);
  } else {
    auto&& ret = f(std::forward<Ts>(args)...);
    if (!ret) {
      return nb::none();
    }
    return nb::cast(*ret);
  }
}

void init_errors(nanobind::module_&);
}

#endif
