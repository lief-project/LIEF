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
#include "Abstract/init.hpp"
#include "pyLIEF.hpp"
#include "pyIOStream.hpp"
#include "pyutils.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

#include "LIEF/Abstract/Parser.hpp"
#include "LIEF/Abstract/Binary.hpp"
#include "LIEF/logging.hpp"

namespace LIEF::py {

template<>
void create<Parser>(nb::module_& m) {

  m.def("parse",
      [] (nb::bytes bytes) {
        std::string raw_str(bytes.c_str(), bytes.size());
        const std::vector<uint8_t> raw = {
          std::make_move_iterator(std::begin(raw_str)),
          std::make_move_iterator(std::end(raw_str))
        };
        return Parser::parse(raw);
      },
      R"delim(
      Parse a binary supported by LIEF from the given bytes and return either:

      - :class:`lief.ELF.Binary`
      - :class:`lief.PE.Binary`
      - :class:`lief.MachO.Binary`

      depending on the given binary format.
      )delim"_doc,
      "raw"_a,
      nb::rv_policy::take_ownership);

  m.def("parse", nb::overload_cast<const std::string&>(&Parser::parse),
      R"delim(
      Parse a binary from the given file path and return either:

      - :class:`lief.ELF.Binary`
      - :class:`lief.PE.Binary`
      - :class:`lief.MachO.Binary`

      depending on the given binary format.
      )delim"_doc,
      "filepath"_a, nb::rv_policy::take_ownership);


  m.def("parse",
      [] (nb::object generic) -> nb::object {
        if (auto path_str = path_to_str(generic)) {
          return nb::cast(Parser::parse(std::move(*path_str)));
        }

        if (auto stream = PyIOStream::from_python(generic)) {
          auto ptr = std::make_unique<PyIOStream>(std::move(*stream));
          return nb::cast(Parser::parse(std::move(ptr)));
        }

        logging::log(logging::LOG_ERR,
                     "LIEF parser interface does not support Python object: " +
                     type2str(generic));
        return nb::none();
      },
      R"delim(
      Parse a binary supported by LIEF from the given Python object and return either:

      - :class:`lief.ELF.Binary`
      - :class:`lief.PE.Binary`
      - :class:`lief.MachO.Binary`

      depending on the given binary format.
      )delim"_doc,
      "parse(obj: io.IOBase | os.PathLike) -> lief.Binary | None"_p,
      "obj"_a, nb::rv_policy::take_ownership);
}
}
