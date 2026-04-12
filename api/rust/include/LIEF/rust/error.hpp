/* Copyright 2024 - 2026 R. Thomas
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
#pragma once
#include "LIEF/errors.hpp"
namespace details {

template<class T>
inline auto make_error(LIEF::result<T> result, uint32_t& err) {
  if (result) {
    err = 0;
    return std::move(*result);
  }
  err = static_cast<uint32_t>(LIEF::get_error(result));
  return T{};
}

inline bool make_ok_error(LIEF::ok_error_t ok_err, uint32_t& err) {
  if (ok_err) {
    err = 0;
    return true;
  }
  err = static_cast<uint32_t>(LIEF::get_error(ok_err));
  return false;
}

}
