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
#include "LIEF/visibility.h"

template< class T >
using add_pointer_t = typename std::add_pointer<T>::type;

template< class T >
using decay_t = typename std::decay<T>::type;

template< class T >
using add_const_t = typename std::add_const<T>::type;

namespace LIEF {

class LIEF_API Object {
  public:
  template<class T>
  using output_t = add_pointer_t<decay_t<T>>;

  template<class T>
  using output_const_t = add_pointer_t<add_const_t<decay_t<T>>>;

  public:
  Object(void);
  Object(const Object& other);
  Object& operator=(const Object& other);

  template<class T>
  LIEF_LOCAL bool is(void) const;

  template<class T>
  LIEF_LOCAL output_t<T> as(void);

  template<class T>
  LIEF_LOCAL output_const_t<T> as(void) const;

  virtual ~Object(void);
  virtual void accept(Visitor& visitor) const = 0;
};
}

#endif
