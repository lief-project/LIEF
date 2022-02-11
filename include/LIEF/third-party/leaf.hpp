/* Copyright 2021 - 2022 R. Thomas
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
#ifndef LIEF_LEAF_H_
#define LIEF_LEAF_H_
#include "LIEF/config.h"

// LEAF raises warnings which pollute the LIEF's warning
// This sequence disables the warning for the include
#if defined(_MSC_VER)
#    pragma warning(push,1)
#elif defined(__clang__)
#    pragma clang system_header
#elif (__GNUC__*100+__GNUC_MINOR__>301)
#    pragma GCC system_header
#endif

#ifndef LIEF_ENABLES_LEAF_EXCEPTIONS // Disable exceptions by default;
  #ifndef BOOST_LEAF_NO_EXCEPTIONS
    #define BOOST_LEAF_NO_EXCEPTIONS
  #else
    #define LIEF_BOOST_NO_EXCEPTIONS_ALREADY_DEFINED
  #endif
#endif

#ifndef LIEF_EXTERNAL_LEAF
#include <LIEF/third-party/internal/leaf.hpp>
#else
#include <boost/leaf.hpp>
#endif


#if defined(BOOST_LEAF_NO_EXCEPTIONS) || defined(BOOST_NO_EXCEPTIONS)
namespace boost {
inline void throw_exception(const std::exception&) {
  std::abort();
}
}
#endif

#if !defined(LIEF_ENABLES_LEAF_EXCEPTIONS) && !defined(LIEF_BOOST_NO_EXCEPTIONS_ALREADY_DEFINED)
#undef BOOST_LEAF_NO_EXCEPTIONS
#endif

#if defined(_MSC_VER)
#pragma warning(pop)
#endif


#endif
