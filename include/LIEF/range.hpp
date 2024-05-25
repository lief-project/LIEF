/* Copyright 2024 R. Thomas
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
#ifndef LIEF_RANGE_H
#define LIEF_RANGE_H
#include <cstdint>
#include <ostream>

namespace LIEF {
struct range_t {
  uint64_t low = 0;
  uint64_t high = 0;

  uint64_t size() const {
    return high - low;
  }

  friend std::ostream& operator<<(std::ostream& os, const range_t& range);
};

}
#endif
