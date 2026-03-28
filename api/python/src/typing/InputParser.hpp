/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#include "pyLIEF.hpp"
#include "typing.hpp"
#include "LIEF/config.h"

#include <memory>
#include <nanobind/nanobind.h>

namespace LIEF {
class BinaryStream;
}

namespace LIEF::py::typing {

constexpr auto out_descr() {
  return nb::detail::union_name(
#if LIEF_PE_SUPPORT
      nb::detail::const_name("_lief.PE.Binary"),
#endif

#if LIEF_OAT_SUPPORT
      nb::detail::const_name("_lief.OAT.Binary"),
#endif

#if LIEF_ELF_SUPPORT
      nb::detail::const_name("_lief.ELF.Binary"),
#endif

#if LIEF_MACHO_SUPPORT
      nb::detail::const_name("_lief.MachO.Binary"),
#endif

#if LIEF_COFF_SUPPORT
      nb::detail::const_name("_lief.COFF.Binary"),
#endif

      nb::detail::const_name("None")
  );
}

struct InputParser : public nanobind::object {
  LIEF_PY_DEFAULT_CTOR(InputParser, nanobind::object);

  NB_OBJECT_DEFAULT(InputParser, object, "Union[str | io.IOBase | os.PathLike | bytes | list[int]]", check)

  std::unique_ptr<BinaryStream> into_stream();

  static bool check(handle /*h*/) {
    return true;
  }
};

struct OutputParser : public nanobind::object {
  LIEF_PY_DEFAULT_CTOR(OutputParser, nanobind::object);

  static constexpr auto Name = out_descr();
  NB_OBJECT_DEFAULT_NONAME(OutputParser, object, check);

  static bool check(handle  /*h*/) {
    return true;
  }
};
}
#endif
