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
#include "LIEF/DEX/Type.hpp"
#include "LIEF/DEX/hash.hpp"

#include "LIEF/DEX/EnumToString.hpp"

#include "pyDEX.hpp"

#define PY_ENUM(x) to_string(x), x

namespace LIEF {
namespace DEX {

template<class T>
using getter_t = T (Type::*)(void) const;

template<class T>
using no_const_getter_t = T (Type::*)(void);

template<class T>
using setter_t = void (Type::*)(T);


template<>
void create<Type>(py::module& m) {

  py::class_<Type, LIEF::Object> pytype(m, "Type", "DEX Type representation");

  py::enum_<Type::TYPES>(pytype, "TYPES")
    .value(PY_ENUM(Type::TYPES::UNKNOWN))
    .value(PY_ENUM(Type::TYPES::ARRAY))
    .value(PY_ENUM(Type::TYPES::PRIMITIVE))
    .value(PY_ENUM(Type::TYPES::CLASS));

  py::enum_<Type::PRIMITIVES>(pytype, "PRIMITIVES")
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
    .def_property_readonly("type",
        &Type::type,
        "" RST_CLASS_REF(lief.DEX.Type.TYPES) " of this object")

    .def_property_readonly("value",
        [] (Type& type) -> py::object {
          switch (type.type()) {
            case Type::TYPES::ARRAY:
              {
                return py::cast(type.array());
              }

            case Type::TYPES::CLASS:
              {
                return py::cast(type.cls(), py::return_value_policy::reference);
              }

            case Type::TYPES::PRIMITIVE:
              {
                return py::cast(type.primitive());
              }

            case Type::TYPES::UNKNOWN:
            default:
              {
                return py::none{};
              }
          }
        },
        "Depending on the " RST_CLASS_REF(lief.DEX.Type.TYPES) ", return "
        " " RST_CLASS_REF(lief.DEX.Class) " or " RST_CLASS_REF(lief.DEX.Type.PRIMITIVES) " or array",
        py::return_value_policy::reference)

    .def_property_readonly("dim",
        &Type::dim,
        "If the current type is an array, return its dimension otherwise 0")

    .def_property_readonly("underlying_array_type",
        static_cast<no_const_getter_t<Type&>>(&Type::underlying_array_type),
        "Underlying type of the array",
        py::return_value_policy::reference)

    .def_static("pretty_name",
        &Type::pretty_name,
        "Pretty name of primitives",
        "primitive"_a)

    .def("__eq__", &Type::operator==)
    .def("__ne__", &Type::operator!=)
    .def("__hash__",
        [] (const Type& type) {
          return Hash::hash(type);
        })

    .def("__str__",
        [] (const Type& type) {
          std::ostringstream stream;
          stream << type;
          return stream.str();
        });
}

}
}
