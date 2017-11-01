/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#include "init.hpp"

#include "LIEF/Abstract/Parser.hpp"

#include <string>

void init_LIEF_Parser_class(py::module& m) {

    m.def("parse",
      static_cast<LIEF::Binary* (*) (const std::string&)>(&LIEF::Parser::parse),
      "Parse the given binary and return a " RST_CLASS_REF(lief.Binary) " object",
      "filepath"_a,
      py::return_value_policy::take_ownership);

  m.def("parse",
      static_cast<LIEF::Binary* (*) (const std::vector<uint8_t>&, const std::string&)>(&LIEF::Parser::parse),
      "Parse the given binary and return a " RST_CLASS_REF(lief.Binary) " object",
      "raw"_a, "name"_a = "",
      py::return_value_policy::take_ownership);


  m.def("parse",
      [] (py::object byteio, const std::string& name) {
        auto&& io = py::module::import("io");
        auto&& RawIOBase = io.attr("RawIOBase");
        auto&& BufferedIOBase = io.attr("BufferedIOBase");
        auto&& TextIOBase = io.attr("TextIOBase");

        py::object rawio;


        if (py::isinstance(byteio, RawIOBase)) {
          rawio = byteio;
        }

        else if (py::isinstance(byteio, BufferedIOBase)) {
          rawio = byteio.attr("raw");
        }

        else if (py::isinstance(byteio, TextIOBase)) {
          rawio = byteio.attr("buffer").attr("raw");
        }

        else {
          throw py::type_error(py::repr(byteio).cast<std::string>().c_str());
        }

        std::string raw_str = static_cast<py::bytes>(rawio.attr("readall")());
        std::vector<uint8_t> raw = {
          std::make_move_iterator(std::begin(raw_str)),
          std::make_move_iterator(std::end(raw_str))};

        return LIEF::Parser::parse(std::move(raw), name);
      },
      "io"_a,
      "name"_a = "",
      py::return_value_policy::take_ownership);
}
