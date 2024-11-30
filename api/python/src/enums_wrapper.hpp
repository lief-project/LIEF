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
#ifndef PY_LIEF_ENUMS_WRAPPER_H
#define PY_LIEF_ENUMS_WRAPPER_H
#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include "pyutils.hpp"
#include <LIEF/logging.hpp>
#include <map>
#include <spdlog/fmt/fmt.h>

#include "LIEF/visibility.h"

namespace LIEF {

template <class Type>
class LIEF_LOCAL enum_ : public nanobind::enum_<Type> {
  public:
  using Base = typename nanobind::enum_<Type>::Base;
  using Underlying = typename nanobind::enum_<Type>::Underlying;
  using nanobind::enum_<Type>::def_prop_ro;
  using nanobind::enum_<Type>::def_static;
  using nanobind::enum_<Type>::def;

  template <typename... Extra>
  NB_INLINE enum_(nanobind::handle scope, const char *name, const Extra &... extra) :
    nanobind::enum_<Type>{scope, name, extra...}
  {
    constexpr bool is_arithmetic = (std::is_same_v<nanobind::is_arithmetic, Extra> || ...);
    constexpr bool is_flag = (std::is_same_v<nanobind::is_flag, Extra> || ...);
    def_static("from_value", [] (Underlying i) { return static_cast<Type>(i); });

    def("__eq__", [](const Type &value, Underlying value2) { return (Underlying) value == value2; });
    def("__eq__", [](const Type &value, Type value2) { return (Underlying) value == (Underlying) value2; });

    def("__ne__", [](const Type &value, Underlying value2) { return (Underlying) value != value2; });
    def("__ne__", [](const Type &value, Type value2) { return (Underlying) value != (Underlying) value2; });

    def("__int__", [](const Type &value) { return (Underlying) value; });
  }
};

}

#endif
