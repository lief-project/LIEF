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
#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include "LIEF/errors.hpp"
#include "LIEF/canbe_unique.hpp"

#pragma once
template<class T>
class Mirror {
  public:
  Mirror(T& impl) : impl_(impl) {}
  Mirror(const T& impl) : impl_(impl) {}
  Mirror(std::unique_ptr<T> impl) : impl_(std::move(impl)) {}

  T& get() { return *impl_; }
  const T& get() const { return *impl_; }

  private:
  LIEF::details::canbe_unique<T> impl_;
};

template<class To, class From>
const To& as(const From* thiz) {
  return static_cast<const To&>(thiz->get());
}

template<class To, class From>
To& as(From* thiz) {
  return static_cast<To&>(thiz->get());
}

namespace details {
template<typename T>
inline std::string to_string(const T& value) {
  std::ostringstream oss;
  oss << value;
  return oss.str();
}

template<class T, class V>
inline std::unique_ptr<T> try_unique(const V* value) {
  return value ? std::make_unique<T>(*value) : nullptr;
}

template<class T, class V>
inline std::unique_ptr<T> try_unique(std::unique_ptr<V> value) {
  return value ? std::make_unique<T>(std::move(value)) : nullptr;
}

template<class T, class V>
inline std::unique_ptr<T> from_result(const LIEF::result<V> value) {
  return value ? std::make_unique<T>(std::move(*value)) : nullptr;
}

// Note(romain): It looks like cxx can't generate a std::vector<> with any integer
// A C++ std::vector was found containing some type that cxx can't accommodate as a vector element (unsigned short)
// Not ideal but let's promote to uint64_t which is supported
template<class T, size_t N>
inline auto make_vector(const std::array<T, N>& array) {
  return std::vector<uint64_t>(std::begin(array), std::end(array));
}

template<class T>
inline auto make_vector(const std::pair<T, T>& p) {
  return std::vector<uint64_t>{p.first, p.second};
}

}
