/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#include "LIEF/Visitable.hpp"
#include "LIEF/Visitor.hpp"


namespace LIEF {
class DLL_PUBLIC Hash : public Visitor {

  public:
  using Visitor::visit;
  Hash(void);
  Hash(size_t init_value);

  template<class T>
  static size_t hash(const T& obj);

  // combine two elements to produce a size_t.
  template<typename U = size_t>
  static inline size_t combine(size_t lhs, U rhs);

  static size_t hash(const std::vector<uint8_t>& raw);
  static size_t hash(const void* raw, size_t size);

  virtual void visit(size_t n) override;
  virtual void visit(const std::string& str) override;
  virtual void visit(const std::u16string& str) override;
  virtual void visit(const std::vector<uint8_t>& raw) override;

  size_t value(void) const;

  protected:
  size_t value_;

};

template<typename U>
size_t Hash::combine(size_t lhs, U rhs) {
  return (lhs ^ rhs) + 0x9e3779b9 + (lhs << 6) + (rhs >> 2);
}


template<class T>
size_t Hash::hash(const T& obj) {
  static_assert(std::is_base_of<Visitable, T>::value, "Hash require inheritance of 'Visitable'");
  Hash hasher;
  obj.accept(hasher);
  return hasher.value();

}

}


#endif
