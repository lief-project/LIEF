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
#include "LIEF/DEX/Type.hpp"
#include "LIEF/DEX/Class.hpp"

#include "LIEF/DEX/EnumToString.hpp"

#include "DEX/pyDEX.hpp"

#include <sstream>
#include <string>
#include <nanobind/stl/string.h>

#define PY_ENUM(x) to_string(x), x

namespace LIEF::DEX::py {

template<>
void create<Type>(nb::module_& m) {

  nb::class_<Type, LIEF::Object> pytype(m, "Type",
      "DEX Type representation"_doc);

  nb::enum_<Type::TYPES>(pytype, "TYPES")
    .value(PY_ENUM(Type::TYPES::UNKNOWN))
    .value(PY_ENUM(Type::TYPES::ARRAY))
    .value(PY_ENUM(Type::TYPES::PRIMITIVE))
    .value(PY_ENUM(Type::TYPES::CLASS));

  nb::enum_<Type::PRIMITIVES>(pytype, "PRIMITIVES")
    .value(PY_ENUM(Type::PRIMITIVES::VOID_T))
    .value(PY_ENUM(Type::PRIMITIVES::BOOLEAN))
    .value(PY_ENUM(Type::PRIMITIVES::BYTE))
    .value(PY_ENUM(Type::PRIMITIVES::SHORT))
    .value(PY_ENUM(Type::PRIMITIVES::CHAR))
    .value(PY_ENUM(Type::PRIMITIVES::INT))
    .value(PY_ENUM(Type::PRIMITIVES::LONG))
    .value(PY_ENUM(Type::PRIMITIVES::FLOAT))
    .value(PY_ENUM(Type::PRIMITIVES::DOUBLE));

  pytype
    .def_prop_ro("type", &Type::type,
        "" RST_CLASS_REF(lief.DEX.Type.TYPES) " of this object"_doc)

    .def_prop_ro("value",
        [] (Type& type) -> nb::object {
          switch (type.type()) {
            case Type::TYPES::ARRAY:
              {
                return nb::cast(type.array());
              }

            case Type::TYPES::CLASS:
              {
                return nb::cast(type.cls(), nb::rv_policy::reference_internal);
              }

            case Type::TYPES::PRIMITIVE:
              {
                return nb::cast(type.primitive());
              }

            case Type::TYPES::UNKNOWN:
            default:
              {
                return nb::none();
              }
          }
        },
        "Depending on the " RST_CLASS_REF(lief.DEX.Type.TYPES) ", return "
        " " RST_CLASS_REF(lief.DEX.Class) " or " RST_CLASS_REF(lief.DEX.Type.PRIMITIVES) " or array"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("dim",
        &Type::dim,
        "If the current type is an array, return its dimension otherwise 0")

    .def_prop_ro("underlying_array_type",
        nb::overload_cast<>(&Type::underlying_array_type, nb::const_),
        "Underlying type of the array"_doc,
        nb::rv_policy::reference_internal)

    .def_static("pretty_name", &Type::pretty_name,
        "Pretty name of primitives"_doc,
        "primitive"_a)

    LIEF_DEFAULT_STR(Type);
}
}
