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
#ifndef LIEF_INTERNAL_UTILS_HEADER
#define LIEF_INTERNAL_UTILS_HEADER
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <unordered_map>


namespace LIEF {
std::string printable_string(const std::string& str);

template<typename HANDLER>
std::vector<std::string> optimize(const HANDLER& container,
                                  std::string(* getter)(const typename HANDLER::value_type&),
                                  size_t& offset_counter,
                                  std::unordered_map<std::string, size_t> *of_map_p = nullptr)
{
  if (container.empty()) {
    return {};
  }

  std::set<std::string> string_table;
  std::vector<std::string> string_table_optimized;
  string_table_optimized.reserve(container.size());

  // reverse all symbol names and sort them so we can merge then in the linear time:
  // aaa, aadd, aaaa, cca, ca -> aaaa, aaa, acc, ac ddaa
  std::transform(std::begin(container), std::end(container),
                 std::inserter(string_table, std::end(string_table)),
                 getter);

  for (const auto& val: string_table) {
    string_table_optimized.emplace_back(val);
    std::reverse(std::begin(string_table_optimized.back()), std::end(string_table_optimized.back()));
  }

  std::sort(std::begin(string_table_optimized), std::end(string_table_optimized),
      [] (const std::string& lhs, const std::string& rhs) {
          bool ret = false;
          if (lhs.size() > rhs.size()) {
            auto res = lhs.compare(0, rhs.size(), rhs);
            ret = (res <= 0);
          } else {
            auto res = rhs.compare(0, lhs.size(), lhs);
            ret = (res > 0);
          }
          return ret;
      }
  );

  // as all elements that can be merged are adjacent we can just go through the list once
  // and memorize one we merged to calculate the offsets later
  std::unordered_map<std::string, std::string> merged_map;
  size_t to_set_idx = 0, cur_elm_idx = 1;
  for (; cur_elm_idx < string_table_optimized.size(); ++cur_elm_idx) {
      auto &cur_elm = string_table_optimized[cur_elm_idx];
      auto &to_set_elm = string_table_optimized[to_set_idx];
      if (to_set_elm.size() >= cur_elm.size()) {
          auto ret = to_set_elm.compare(0, cur_elm.size(), cur_elm);
          if (ret == 0) {
            // when memorizing reverse back symbol names
            std::string rev_cur_elm = cur_elm;
            std::string rev_to_set_elm = to_set_elm;
            std::reverse(std::begin(rev_cur_elm), std::end(rev_cur_elm));
            std::reverse(std::begin(rev_to_set_elm), std::end(rev_to_set_elm));
            merged_map[rev_cur_elm] = rev_to_set_elm;
            continue;
          }
      }
      ++to_set_idx;
      std::swap(string_table_optimized[to_set_idx], cur_elm);
  }
  // if the first one is empty
  if (string_table_optimized[0].empty()) {
    std::swap(string_table_optimized[0], string_table_optimized[to_set_idx]);
    --to_set_idx;
  }
  string_table_optimized.resize(to_set_idx + 1);

  //reverse symbols back and sort them again
  for (auto &val: string_table_optimized) {
    std::reverse(std::begin(val), std::end(val));
  }
  std::sort(std::begin(string_table_optimized), std::end(string_table_optimized));

  if (of_map_p != nullptr) {
    std::unordered_map<std::string, size_t>& offset_map = *of_map_p;
    offset_map[""] = 0;
    for (const auto &v : string_table_optimized) {
      offset_map[v] = offset_counter;
      offset_counter += v.size() + 1;
    }
    for (const auto &kv : merged_map) {
      offset_map[kv.first] = offset_map[kv.second] + (kv.second.size() - kv.first.size());
    }
  }

  return string_table_optimized;
}
}

#endif
