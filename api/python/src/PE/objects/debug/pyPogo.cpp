/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#include "PE/pyPE.hpp"
#include "pyIterator.hpp"
#include "enums_wrapper.hpp"

#include "LIEF/PE/debug/Pogo.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

#define PY_ENUM(x) to_string(x), x

namespace LIEF::PE::py {

template<>
void create<Pogo>(nb::module_& m) {
  using namespace LIEF::py;
  nb::class_<Pogo, Debug> pogo(m, "Pogo");

  init_ref_iterator<Pogo::it_entries>(pogo, "it_entries");

  enum_<Pogo::SIGNATURES>(pogo, "SIGNATURES")
    .value(PY_ENUM(Pogo::SIGNATURES::UNKNOWN))
    .value(PY_ENUM(Pogo::SIGNATURES::ZERO))
    .value(PY_ENUM(Pogo::SIGNATURES::LCTG))
    .value(PY_ENUM(Pogo::SIGNATURES::PGI));

  pogo
    .def(nb::init<>())

    .def_prop_ro("entries",
        nb::overload_cast<>(&Pogo::entries),
        nb::keep_alive<0, 1>())

    .def_prop_ro("signature",
        nb::overload_cast<>(&Pogo::signature, nb::const_),
        "Type of the pogo (" RST_CLASS_REF(lief.PE.Pogo.SIGNATURES) ")"_doc)

    LIEF_DEFAULT_STR(Pogo);
}
}
