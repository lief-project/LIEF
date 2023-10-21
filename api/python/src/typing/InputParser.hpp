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
#ifndef PY_LIEF_TYPING_INPUT_PARSER_H
#define PY_LIEF_TYPING_INPUT_PARSER_H
#include "typing.hpp"

namespace LIEF::py::typing {
struct InputParser {
  LIEF_PY_DEFAULT_CTOR(InputParser, nanobind::object);
  LIEF_PY_DEFAULT_WRAPPER(InputParser);
};
}

NAMESPACE_BEGIN(NB_NAMESPACE)
NAMESPACE_BEGIN(detail)
template <> struct type_caster<LIEF::py::typing::InputParser> {
  using Type = LIEF::py::typing::InputParser;
  NB_TYPE_CASTER(LIEF::py::typing::InputParser, const_name("Union[io.IOBase | os.PathLike]"));

  bool from_python(handle src, uint8_t, cleanup_list *) noexcept {
    value = nanobind::object(src, nanobind::detail::borrow_t());
    return true;
  }
  static handle from_cpp(const Type &value, rv_policy,
                         cleanup_list *) noexcept {
    return nanobind::none();
  }
};
NAMESPACE_END(detail)
NAMESPACE_END(NB_NAMESPACE)

#endif
