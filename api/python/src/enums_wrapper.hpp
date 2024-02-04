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


template<class Type, class Scalar = typename std::underlying_type_t<Type>>
static inline
std::map<Scalar, std::string> get_enums_map(const nanobind::object& value) {
  static constexpr auto NANOBIND_ENTRIES = "@entries";
  auto flags = nanobind::cast<Type>(value);
  auto int_value = static_cast<Scalar>(flags);
  const nanobind::dict entries = value.attr(NANOBIND_ENTRIES);
  std::map<Scalar, std::string> entries_map;
  for (const auto& [value, info] : entries) {
    auto enum_int    = nanobind::cast<Scalar>(value);
    auto name        = nanobind::cast<std::string>(info[0]);
    auto enume_typed = nanobind::cast<Type>(info[2]);
    entries_map[enum_int] = std::move(name);
  }
  return entries_map;
}

template<class Type, class Scalar = typename std::underlying_type_t<Type>>
static inline
std::string flag2str(const nanobind::object& value, bool full_type) {
  auto flags = nanobind::cast<Type>(value);
  auto int_value = static_cast<Scalar>(flags);
  const std::map<Scalar, std::string>& entries_map = get_enums_map<Type>(value);

  if (auto it = entries_map.find(int_value); it != entries_map.end()) {
    return LIEF::py::type2str(value) + '.' + it->second;
  }

  std::string flags_str;
  for (const auto& [entry_value, name] : entries_map) {
    if (entry_value == 0) {
      continue;
    }

    if ((int_value & entry_value) == entry_value) {
      if (!flags_str.empty()) {
        flags_str += " | ";
      }
      if (full_type) {
        flags_str += LIEF::py::type2str(value) + '.' + name;
      } else {
        flags_str += name;
      }
    }
  }
  return flags_str;
}


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
      def("__repr__", [] (const nanobind::object &value) {
          auto typed_value = nanobind::cast<Type>(value);
          auto int_value = static_cast<Scalar>(typed_value);
         return fmt::format("<{}.{}: {}>", LIEF::py::type2str(value), flag2str<Type>(value, /*full_type*/false), int_value);
      });
      def("__str__", [] (const nanobind::object &value) {
        return flag2str<Type>(value, /*full_type*/true);
      });

    }



  }
};

}

#endif
