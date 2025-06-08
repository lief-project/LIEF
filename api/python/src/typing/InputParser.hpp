/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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
#include "LIEF/config.h"
#include <memory>

namespace LIEF {
class BinaryStream;
}

namespace LIEF::py::typing {
struct InputParser : public nanobind::object {
  LIEF_PY_DEFAULT_CTOR(InputParser, nanobind::object);

  NB_OBJECT_DEFAULT(InputParser, object, "Union[io.IOBase | os.PathLike | bytes | list[int]]", check)

  std::unique_ptr<BinaryStream> into_stream();

  static bool check(handle h) {
    return true;
  }
};

struct OutputParser : public nanobind::object {
  LIEF_PY_DEFAULT_CTOR(OutputParser, nanobind::object);

  NB_OBJECT_DEFAULT(OutputParser, object,
  "Union["
#if LIEF_PE_SUPPORT
  "lief.PE.Binary,"
#endif

#if LIEF_OAT_SUPPORT
  "lief.OAT.Binary,"
#endif

#if LIEF_ELF_SUPPORT
  "lief.ELF.Binary,"
#endif

#if LIEF_MACHO_SUPPORT
  "lief.MachO.Binary,"
#endif

#if LIEF_COFF_SUPPORT
  "lief.COFF.Binary,"
#endif

  "None]", check);

  static bool check(handle h) {
    return true;
  }
};
}
#endif
