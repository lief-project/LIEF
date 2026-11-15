/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#ifndef LIEF_INTERNAL_ENDIANNESS_H
#define LIEF_INTERNAL_ENDIANNESS_H
#include "LIEF/Abstract/Header.hpp"
#include "LIEF/ELF/Header.hpp"

namespace LIEF {

template<class T>
struct endianness_traits;

template<>
struct endianness_traits<Header::ENDIANNESS> {
  static constexpr auto LITTLE = Header::ENDIANNESS::LITTLE;
  static constexpr auto BIG = Header::ENDIANNESS::BIG;
};

template<>
struct endianness_traits<ELF::Header::ELF_DATA> {
  static constexpr auto LITTLE = ELF::Header::ELF_DATA::LSB;
  static constexpr auto BIG = ELF::Header::ELF_DATA::MSB;
};

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) &&                   \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
template<class T>
inline constexpr T HOST_ENDIANNESS = endianness_traits<T>::BIG;

template<class T>
inline constexpr T SWAPPED_ENDIANNESS = endianness_traits<T>::LITTLE;
#else
// Also without __BYTE_ORDER__ (e.g. MSVC): the host is assumed little-endian
template<class T>
inline constexpr T HOST_ENDIANNESS = endianness_traits<T>::LITTLE;

template<class T>
inline constexpr T SWAPPED_ENDIANNESS = endianness_traits<T>::BIG;
#endif
}
#endif
