/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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
  Class_(Ty obj_) : obj(std::move(obj_)) {}

#define LIEF_PY_DEFAULT_WRAPPER(Class_)       \
  Class_(const Class_&) = default;            \
  Class_(Class_&&) = default;                 \
                                              \
  Class_& operator=(const Class_&) = default; \
  Class_& operator=(Class_&&) = default;      \
                                              \
  operator nanobind::object () const {        \
    return obj;                               \
  }                                           \
                                              \
  operator nanobind::object && () {           \
    return std::move(obj);                    \
  }                                           \
                                              \
  Class_() : obj(nanobind::none()) {}         \
  nanobind::object obj;


#define LIEF_PY_DEFAULT_NB_CASTER(Class_, Typing)                   \
NAMESPACE_BEGIN(NB_NAMESPACE)                                       \
NAMESPACE_BEGIN(detail)                                             \
template <> struct type_caster<Class_> {                            \
  NB_TYPE_CASTER(Class_, const_name(Typing));                       \
                                                                    \
  bool from_python(handle src, uint8_t, cleanup_list *) noexcept {  \
    return false;                                                   \
  }                                                                 \
  static handle from_cpp(const Class_ &value, rv_policy,            \
                         cleanup_list *) noexcept {                 \
    return value.obj;                                               \
  }                                                                 \
};                                                                  \
NAMESPACE_END(detail)                                               \
NAMESPACE_END(NB_NAMESPACE)

#endif
