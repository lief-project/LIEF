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
#ifndef LIEF_VISITABLE_H_
#define LIEF_VISITABLE_H_

#include "LIEF/Visitor.hpp"

template< class T >
using add_pointer_t = typename std::add_pointer<T>::type;

template< class T >
using decay_t = typename std::decay<T>::type;

namespace LIEF {

class Visitable {
  public:
  Visitable(void);
  Visitable(const Visitable& other);
  Visitable& operator=(const Visitable& other);

  template<class T>
  bool is(void) {
    return typeid(*this) == typeid(T);
  }

  template<class T>
  add_pointer_t<decay_t<T>> as(void) {
    return dynamic_cast<add_pointer_t<decay_t<T>>>(this);
  }

  virtual ~Visitable(void);
  virtual void accept(Visitor& visitor) const = 0;
};
}

#endif
