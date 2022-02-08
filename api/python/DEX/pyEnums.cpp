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
#include "pyDEX.hpp"
#include "LIEF/DEX/enums.hpp"
#include "LIEF/DEX/EnumToString.hpp"

#define PY_ENUM(x) to_string(x), x

namespace LIEF {
namespace DEX {
void init_enums(py::module& m) {

  py::enum_<ACCESS_FLAGS>(m, "ACCESS_FLAGS")
    .value(PY_ENUM(ACCESS_FLAGS::ACC_UNKNOWN))
    .value(PY_ENUM(ACCESS_FLAGS::ACC_PUBLIC))
    .value(PY_ENUM(ACCESS_FLAGS::ACC_PRIVATE))
    .value(PY_ENUM(ACCESS_FLAGS::ACC_PROTECTED))
    .value(PY_ENUM(ACCESS_FLAGS::ACC_STATIC))
    .value(PY_ENUM(ACCESS_FLAGS::ACC_FINAL))
    .value(PY_ENUM(ACCESS_FLAGS::ACC_SYNCHRONIZED))
    .value(PY_ENUM(ACCESS_FLAGS::ACC_VOLATILE))
    .value("BRIDGE",    ACCESS_FLAGS::ACC_BRIDGE)
    .value("TRANSIENT", ACCESS_FLAGS::ACC_TRANSIENT)
    .value(PY_ENUM(ACCESS_FLAGS::ACC_VARARGS))
    .value(PY_ENUM(ACCESS_FLAGS::ACC_NATIVE))
    .value(PY_ENUM(ACCESS_FLAGS::ACC_INTERFACE))
    .value(PY_ENUM(ACCESS_FLAGS::ACC_ABSTRACT))
    .value(PY_ENUM(ACCESS_FLAGS::ACC_STRICT))
    .value(PY_ENUM(ACCESS_FLAGS::ACC_SYNTHETIC))
    .value(PY_ENUM(ACCESS_FLAGS::ACC_ANNOTATION))
    .value(PY_ENUM(ACCESS_FLAGS::ACC_ENUM))
    .value(PY_ENUM(ACCESS_FLAGS::ACC_CONSTRUCTOR))
    .value(PY_ENUM(ACCESS_FLAGS::ACC_DECLARED_SYNCHRONIZED));

}
}
}
