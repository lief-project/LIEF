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
#ifndef LIEF_ENUM_TO_STRING_H
#define LIEF_ENUM_TO_STRING_H
#include "LIEF/visibility.h"

#include "LIEF/Abstract/enums.hpp"
#include "LIEF/Abstract/Binary.hpp"

namespace LIEF {
LIEF_API const char* to_string(ARCHITECTURES e);
LIEF_API const char* to_string(OBJECT_TYPES e);
LIEF_API const char* to_string(MODES e);
LIEF_API const char* to_string(ENDIANNESS e);
LIEF_API const char* to_string(Function::FLAGS e);
} // namespace LIEF

#endif

