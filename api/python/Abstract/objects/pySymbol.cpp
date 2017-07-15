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
#include "LIEF/Abstract/Symbol.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = const T& (LIEF::Symbol::*)(void) const;

template<class T>
using setter_t = void (LIEF::Symbol::*)(const T&);


class PySymbol : public LIEF::Symbol {
  public:
    using LIEF::Symbol::Symbol;

    virtual const std::string& name(void) const override {
      PYBIND11_OVERLOAD(const std::string&, LIEF::Symbol, name,);
    };

    virtual void name(const std::string& name) override {
      PYBIND11_OVERLOAD(void, LIEF::Symbol, name, name);
    };
};


void init_LIEF_Symbol_class(py::module& m) {

  py::class_<LIEF::Symbol, PySymbol>(m, "Symbol")
    .def(py::init())

    .def_property("name",
        [] (const LIEF::Symbol& obj) {
          return safe_string_converter(obj.name());
        },
        static_cast<setter_t<std::string>>(&LIEF::Symbol::name),
        "Symbol's name")

    .def("__str__",
        [] (const LIEF::Symbol& symbol)
        {
          std::ostringstream stream;
          stream << symbol;
          std::string str = stream.str();
          return str;
        });
}
