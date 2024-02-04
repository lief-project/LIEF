/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#ifndef PY_LIEF_TYPING_H
#define PY_LIEF_TYPING_H
#include <nanobind/nanobind.h>

#define LIEF_PY_DEFAULT_CTOR(Class_, Ty) \
  Class_(Ty obj_) : nanobind::object(obj_, nanobind::detail::borrow_t{}) {}

#define NB_OBJECT_DEFAULT_NONAME(Type, Parent, Check)      \
public:                                                    \
    NB_INLINE Type(handle h, ::nanobind::detail::borrow_t) \
        : Parent(h, ::nanobind::detail::borrow_t{}) { }    \
    NB_INLINE Type(handle h, ::nanobind::detail::steal_t)  \
        : Parent(h, ::nanobind::detail::steal_t{}) { }     \
    NB_INLINE static bool check_(handle h) {               \
        return Check(h.ptr());                             \
    }                                                      \
    NB_INLINE Type() : Parent() {}
#endif
