/* Copyright 2021 - 2024 R. Thomas
 * Copyright 2021 - 2024 Quarkslab
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
#include "LIEF/BinaryStream/Convert.hpp"
#include "LIEF/BinaryStream/BinaryStream.hpp"

#define TMPL_DECL(T) template<> void swap_endian<T>(T* u) { *u = BinaryStream::swap_endian(*u); }

/* In place conversions for BinaryStream/VectorStream data */
namespace LIEF {
namespace Convert {

TMPL_DECL(char)
TMPL_DECL(char16_t)

TMPL_DECL(uint8_t)
TMPL_DECL(uint16_t)
TMPL_DECL(uint32_t)
TMPL_DECL(uint64_t)

TMPL_DECL(int8_t)
TMPL_DECL(int16_t)
TMPL_DECL(int32_t)
TMPL_DECL(int64_t)


}
}
