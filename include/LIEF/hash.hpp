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
#ifndef LIEF_HASH_H_
#define LIEF_HASH_H_

#include <iostream>

#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"
#include "LIEF/Visitor.hpp"
#include "LIEF/span.hpp"


namespace LIEF {
LIEF_API size_t hash(const Object& v);
LIEF_API size_t hash(const std::vector<uint8_t>& raw);
LIEF_API size_t hash(span<const uint8_t> raw);

class LIEF_API Hash : public Visitor {

  public:
  template<class H = Hash>
  static size_t hash(const Object& obj);

  static size_t hash(const std::vector<uint8_t>& raw);
  static size_t hash(span<const uint8_t> raw);
  static size_t hash(const void* raw, size_t size);

  // combine two elements to produce a size_t.
  template<typename U = size_t>
  static inline size_t combine(size_t lhs, U rhs);

  public:
  using Visitor::visit;
  Hash();
  Hash(size_t init_value);

  virtual Hash& process(const Object& obj);
  virtual Hash& process(size_t integer);
  virtual Hash& process(const std::string& str);
  virtual Hash& process(const std::u16string& str);
  virtual Hash& process(const std::vector<uint8_t>& raw);
  virtual Hash& process(span<const uint8_t> raw);

  template<class T, typename = typename std::enable_if<std::is_enum<T>::value>::type>
  Hash& process(T v) {
    return process(static_cast<size_t>(v));
  }

  template<class It>
  Hash& process(typename It::iterator v) {
    return process(std::begin(v), std::end(v));
  }


  template<class T, size_t N>
  Hash& process(const std::array<T, N>& array) {
    process(std::begin(array), std::end(array));
    return *this;
  }

  template<class T>
  Hash& process(const std::vector<T>& vector) {
    process(std::begin(vector), std::end(vector));
    return *this;
  }

  template<class T>
  Hash& process(const std::set<T>& set) {
    process(std::begin(set), std::end(set));
    return *this;
  }

  template<class U, class V>
  Hash& process(const std::pair<U, V>& p) {
    process(p.first);
    process(p.second);
    return *this;
  }

  template<class InputIt>
  Hash& process(InputIt begin, InputIt end) {
    for (auto&& it = begin; it != end; ++it) {
      process(*it);
    }
    return *this;
  }

  size_t value() const;
  virtual ~Hash();

  protected:
  size_t value_;

};

template<typename U>
size_t Hash::combine(size_t lhs, U rhs) {
  return (lhs ^ rhs) + 0x9e3779b9 + (lhs << 6) + (rhs >> 2);
}


template<class H>
size_t Hash::hash(const Object& obj) {
  H h;
  obj.accept(h);
  return h.value();
}

}


#endif
