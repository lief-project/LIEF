/* Copyright 2022 - 2024 R. Thomas
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
#include "LIEF/range.hpp"

#include <algorithm>
#include <vector>

class Range {
  public:
  uint64_t low = 0;
  uint64_t high = 0;
};

namespace details {
inline Range make_range(LIEF::range_t range) {
  return Range{range.low, range.high};
}

inline std::vector<Range> make_range(const std::vector<LIEF::range_t>& ranges) {
  std::vector<Range> results;
  results.reserve(ranges.size());
  std::transform(ranges.begin(), ranges.end(), std::back_inserter(results),
    [] (const LIEF::range_t& R) {
      return make_range(R);
    }
  );
  return results;
}
}

