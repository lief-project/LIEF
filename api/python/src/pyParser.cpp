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
#include "Abstract/init.hpp"
#include "pyLIEF.hpp"
#include "typing/InputParser.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

#include "LIEF/Abstract/Parser.hpp"
#include "LIEF/BinaryStream/BinaryStream.hpp"

#include "LIEF/config.h"

#if LIEF_PE_SUPPORT
#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/Parser.hpp"
#include "LIEF/PE/Binary.hpp"
#endif

#if LIEF_ELF_SUPPORT
#include "LIEF/ELF/utils.hpp"
#include "LIEF/ELF/Parser.hpp"
#include "LIEF/ELF/Binary.hpp"
#endif

#if LIEF_OAT_SUPPORT
#include "LIEF/OAT/utils.hpp"
#include "LIEF/OAT/Parser.hpp"
#include "LIEF/OAT/Binary.hpp"
#endif

#if LIEF_MACHO_SUPPORT
#include "LIEF/MachO/utils.hpp"
#include "LIEF/MachO/Parser.hpp"
#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/FatBinary.hpp"
#endif

#if LIEF_COFF_SUPPORT
#include "LIEF/COFF/utils.hpp"
#include "LIEF/COFF/Parser.hpp"
#include "LIEF/COFF/Binary.hpp"
#endif

namespace LIEF::py {

typing::OutputParser from_stream(std::unique_ptr<BinaryStream> stream) {
  if (stream == nullptr) {
    return nb::none();
  }

  #if LIEF_PE_SUPPORT
  if (LIEF::PE::is_pe(*stream)) {
    return nb::cast(LIEF::PE::Parser::parse(std::move(stream)));
  }
  #endif

  #if LIEF_ELF_SUPPORT
  if (LIEF::ELF::is_elf(*stream)) {
    return nb::cast(LIEF::ELF::Parser::parse(std::move(stream)));
  }
  #endif

  #if LIEF_MACHO_SUPPORT
  if (LIEF::MachO::is_macho(*stream)) {
    std::unique_ptr<LIEF::MachO::FatBinary> fat =
      LIEF::MachO::Parser::parse(std::move(stream));

    // NOTE(romain): We could nb::cast the fat binary object but
    // to avoid a breaking change in the logic of parse() we return a
    // `LIEF::MachO::Binary` as we did since the beginning.
    //
    // We could introduce this breaking change later though.
    if (fat == nullptr || fat->empty()) {
      return nb::none();
    }
    return nb::cast(fat->take(0));
  }
  #endif

  #if LIEF_COFF_SUPPORT
  if (LIEF::COFF::is_coff(*stream)) {
    return nb::cast(LIEF::COFF::Parser::parse(std::move(stream)));
  }
  #endif

  return nb::none();
}

template<>
void create<Parser>(nb::module_& m) {
  m.def("parse",
      [] (typing::InputParser generic) -> typing::OutputParser {
        return from_stream(generic.into_stream());
      },
      R"delim(
      )delim"_doc,
      "obj"_a, nb::rv_policy::take_ownership);
}
}
