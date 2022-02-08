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
#ifndef PY_LIEF_ABSTRACT_H_
#define PY_LIEF_ABSTRACT_H_

#include "pyLIEF.hpp"
#include "LIEF/Abstract.hpp"

#define SPECIALIZE_CREATE(X)      \
  template<>                      \
  void create<X>(py::module&)

#define CREATE(X,Y) create<X>(Y)

namespace LIEF {
template<class T>
void create(py::module&);

void init_python_module(py::module& m);
void init_objects(py::module&);
void init_enums(py::module&);

SPECIALIZE_CREATE(Header);
SPECIALIZE_CREATE(Binary);
SPECIALIZE_CREATE(Section);
SPECIALIZE_CREATE(Symbol);
SPECIALIZE_CREATE(Parser);
SPECIALIZE_CREATE(Relocation);
SPECIALIZE_CREATE(Function);
}
#endif
