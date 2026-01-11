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

#if LIEF_PE_SUPPORT
#include "LIEF/PE/Binary.hpp"
#endif

#if LIEF_ELF_SUPPORT
#include "LIEF/ELF/Binary.hpp"
#endif

#if LIEF_OAT_SUPPORT
#include "LIEF/OAT/Binary.hpp"
#endif

#if LIEF_MACHO_SUPPORT
#include "LIEF/MachO/Binary.hpp"
#endif

#if LIEF_COFF_SUPPORT
#include "LIEF/COFF/Binary.hpp"
#endif

namespace LIEF {
class BinaryStream;
}


namespace LIEF::py::typing {

constexpr auto out_descr() {
  return nb::detail::union_name(
#if LIEF_PE_SUPPORT
      nb::detail::make_caster<LIEF::PE::Binary>::Name,
#endif

#if LIEF_OAT_SUPPORT
      nb::detail::make_caster<LIEF::OAT::Binary>::Name,
#endif

#if LIEF_ELF_SUPPORT
      nb::detail::make_caster<LIEF::ELF::Binary>::Name,
#endif

#if LIEF_MACHO_SUPPORT
      nb::detail::make_caster<LIEF::MachO::Binary>::Name,
#endif

#if LIEF_COFF_SUPPORT
      nb::detail::make_caster<LIEF::COFF::Binary>::Name,
#endif

      nb::detail::const_name("None")
  );
}

struct InputParser : public nanobind::object {
  LIEF_PY_DEFAULT_CTOR(InputParser, nanobind::object);

  NB_OBJECT_DEFAULT(InputParser, object, "Union[str | io.IOBase | os.PathLike | bytes | list[int]]", check)

  std::unique_ptr<BinaryStream> into_stream();

  static bool check(handle h) {
    return true;
  }
};

struct OutputParser : public nanobind::object {
  LIEF_PY_DEFAULT_CTOR(OutputParser, nanobind::object);

  static constexpr auto Name = out_descr();
  NB_OBJECT_DEFAULT_NONAME(OutputParser, object, check);

  static bool check(handle h) {
    return true;
  }
};
}
#endif
