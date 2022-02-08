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
#ifndef PY_LIEF_ENUMS_WRAPPER_H_
#define PY_LIEF_ENUMS_WRAPPER_H_
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "LIEF/visibility.h"

namespace py = pybind11;

namespace LIEF {

template <class Type>
class LIEF_LOCAL enum_ : public pybind11::enum_<Type> {
  public:
  using py::enum_<Type>::def;
  using py::enum_<Type>::def_property_readonly_static;
  using Scalar = typename py::enum_<Type>::Scalar;

  template <typename... Extra>
  enum_(const py::handle &scope, const char *name, const Extra&... extra) :
    py::enum_<Type>{scope, name, extra...}
  {
    constexpr bool is_arithmetic = py::detail::any_of<std::is_same<py::arithmetic, Extra>...>::value;
    def("__eq__", [](const Type &value, Scalar value2) { return (Scalar) value == value2; });
    def("__ne__", [](const Type &value, Scalar value2) { return (Scalar) value != value2; });
    if (is_arithmetic) {
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
      def("__or__", [](const Type &value, const Type &value2) { return (Scalar) value | (Scalar) value2; });
      def("__xor__", [](const Type &value, const Type &value2) { return (Scalar) value ^ (Scalar) value2; });
    }
  }
};

}

#endif
