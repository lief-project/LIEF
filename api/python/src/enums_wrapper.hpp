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
#ifndef PY_LIEF_ENUMS_WRAPPER_H
#define PY_LIEF_ENUMS_WRAPPER_H
#include <nanobind/nanobind.h>
#include <LIEF/logging.hpp>

#include "LIEF/visibility.h"

namespace LIEF {

template <class Type>
class LIEF_LOCAL enum_ : public nanobind::enum_<Type> {
  public:
  using nanobind::enum_<Type>::def;
  using nanobind::enum_<Type>::def_static;
  using Scalar = typename std::underlying_type_t<Type>;
  using nanobind::class_<Type>::def_prop_ro;

  template <typename... Extra>
  enum_(const nanobind::handle &scope, const char *name, const Extra&... extra) :
    nanobind::enum_<Type>{scope, name, extra...}
  {
    constexpr bool is_arithmetic = (std::is_same_v<nanobind::is_arithmetic, Extra> || ...);
    /* These are methods not (yet?) implemented in nanobind */
    /* ------------------------------------------------------------------------*/
    def_prop_ro("value", [] (const Type &value) { return (Scalar) value; },
        "The underlying integer value");
    def_static("from_value", [] (Scalar i) { return static_cast<Type>(i); });
    /* ------------------------------------------------------------------------*/
    def("__eq__", [](const Type &value, Scalar value2) { return (Scalar) value == value2; });
    def("__ne__", [](const Type &value, Scalar value2) { return (Scalar) value != value2; });
    if constexpr (is_arithmetic) {
      def("__lt__", [](const Type &value, Scalar value2) { return (Scalar) value < value2; });
      def("__gt__", [](const Type &value, Scalar value2) { return (Scalar) value > value2; });
      def("__le__", [](const Type &value, Scalar value2) { return (Scalar) value <= value2; });
      def("__ge__", [](const Type &value, Scalar value2) { return (Scalar) value >= value2; });
      def("__invert__", [](const Type &value) { return ~((Scalar) value); });
      def("__and__", [](const Type &value, Scalar value2) { return (Scalar) value & value2; });
      def("__or__", [](const Type &value, Scalar value2) { return (Scalar) value | value2; });
      def("__xor__", [](const Type &value, Scalar value2) { return (Scalar) value ^ value2; });
      def("__rand__", [](const Type &value, Scalar value2) { return (Scalar) value & value2; });
      def("__ror__", [](const Type &value, Scalar value2) { return (Scalar) value | value2; });
      def("__rxor__", [](const Type &value, Scalar value2) { return (Scalar) value ^ value2; });
      def("__and__", [](const Type &value, const Type &value2) { return (Scalar) value & (Scalar) value2; });
      def("__or__", [](const Type &value, const Type &value2) { return Type((Scalar) value | (Scalar) value2); });
      def("__xor__", [](const Type &value, const Type &value2) { return (Scalar) value ^ (Scalar) value2; });
    }
  }
};

}

#endif
