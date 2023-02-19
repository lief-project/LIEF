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
#include "pyPE.hpp"

#include "PyIOStream.hpp"
#include "LIEF/PE/Parser.hpp"
#include "LIEF/logging.hpp"

#include <string>

namespace LIEF {
namespace PE {

template<>
void create<Parser>(py::module& m) {

    m.def("parse",
      static_cast<std::unique_ptr<Binary> (*) (const std::string&)>(&Parser::parse),
      "Parse the PE binary from the given **file path** and return a " RST_CLASS_REF(lief.PE.Binary) " object",
      "filename"_a,
      py::return_value_policy::take_ownership);

    m.def("parse",
      static_cast<std::unique_ptr<Binary> (*) (std::vector<uint8_t>, const std::string&)>(&Parser::parse),
      "Parse the PE binary from the given **list of bytes** and return a :class:`lief.PE.Binary` object",
      "raw"_a, "name"_a = "",
      py::return_value_policy::take_ownership);


    m.def("parse",
      [] (py::object byteio, const std::string& name) -> py::object {
        if (auto stream = PyIOStream::from_python(byteio)) {
          auto ptr = std::make_unique<PyIOStream>(std::move(*stream));
          return py::cast(PE::Parser::parse(std::move(ptr), name));
        }
        logging::log(logging::LOG_ERR, "Can't create a LIEF stream interface over the provided io");
        return py::none();
      },
      "Parse the PE binary from the given Python IO interface and return a :class:`lief.PE.Binary` object",
      "io"_a, "name"_a = "",
      py::return_value_policy::take_ownership);
}

}
}
