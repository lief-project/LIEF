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

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

#include "LIEF/Abstract/Parser.hpp"
#include "LIEF/BinaryStream/BinaryStream.hpp"

#include "LIEF/config.h"

#if LIEF_PE_SUPPORT
  #include "LIEF/PE/Binary.hpp"
  #include "LIEF/PE/Parser.hpp"
  #include "LIEF/PE/utils.hpp"
#endif

#if LIEF_ELF_SUPPORT
  #include "LIEF/ELF/Binary.hpp"
  #include "LIEF/ELF/Parser.hpp"
  #include "LIEF/ELF/utils.hpp"
#endif

#if LIEF_MACHO_SUPPORT
  #include "LIEF/MachO/Binary.hpp"
  #include "LIEF/MachO/FatBinary.hpp"
  #include "LIEF/MachO/Parser.hpp"
  #include "LIEF/MachO/utils.hpp"
#endif

#if LIEF_COFF_SUPPORT
  #include "LIEF/COFF/Binary.hpp"
  #include "LIEF/COFF/Parser.hpp"
  #include "LIEF/COFF/utils.hpp"
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

typing::OutputParser parse_dump_from_stream(std::unique_ptr<BinaryStream> stream,
                                            uint64_t addr) {
  if (stream == nullptr) {
    return nb::none();
  }

#if LIEF_PE_SUPPORT
  if (LIEF::PE::is_pe(*stream)) {
    return nb::cast(LIEF::PE::Parser::parse_from_dump(std::move(stream), addr));
  }
#endif

#if LIEF_ELF_SUPPORT
  if (LIEF::ELF::is_elf(*stream)) {
    return nb::cast(LIEF::ELF::Parser::parse_from_dump(std::move(stream), addr));
  }
#endif

#if LIEF_MACHO_SUPPORT
  if (LIEF::MachO::is_macho(*stream)) {
    std::unique_ptr<LIEF::MachO::FatBinary> fat =
        LIEF::MachO::Parser::parse_from_dump(std::move(stream), addr);

    if (fat == nullptr || fat->empty()) {
      return nb::none();
    }
    return nb::cast(fat->take(0));
  }
#endif

  return nb::none();
}

template<>
void create<Parser>(nb::module_& m) {
  m.def(
      "parse",
      [](typing::InputParser generic) -> typing::OutputParser {
        return from_stream(generic.into_stream());
      },
      R"delim(
      Parse a binary supported by LIEF (ELF, PE, Mach-O, ...) from the given
      Python object and return the corresponding :class:`~lief.Binary` object.
      )delim"_doc,
      "obj"_a, nb::rv_policy::take_ownership
  );

  m.def(
      "parse_from_dump",
      [](typing::InputParser generic, uint64_t addr) -> typing::OutputParser {
        return parse_dump_from_stream(generic.into_stream(), addr);
      },
      R"delim(
      Parse a binary (ELF, PE, Mach-O, ...) from a memory dump.

      A dump is a raw capture of the process' memory that was mapped starting at
      the virtual address ``addr`` (given as the second parameter). The format is
      auto-detected from the content of the dump.
      )delim"_doc,
      "obj"_a, "addr"_a, nb::rv_policy::take_ownership
  );
}
}
