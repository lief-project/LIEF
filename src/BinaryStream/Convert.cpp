/* Copyright 2021 R. Thomas
 * Copyright 2021 Quarkslab
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

/* In place conversions for BinaryStream/VectorStream data */

namespace LIEF {
namespace Convert {

template<typename T>
void swap_endian(T *v) {
  static_assert(std::is_integral<T>::value, "Only integer types can use generic endian swap");
  *v = BinaryStream::swap_endian(*v);
}

/*
 * Force instantiation of template for types used
 */
template void swap_endian<uint16_t>(uint16_t *v);
template void swap_endian<uint32_t>(uint32_t *v);
template void swap_endian<uint64_t>(uint64_t *v);
template void swap_endian<char16_t>(char16_t *v);

}
}
