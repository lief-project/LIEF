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
#include "LIEF/DEX/Prototype.hpp"
#include "LIEF/DEX/Type.hpp"

#include "DEX/pyDEX.hpp"
#include "pyIterator.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

namespace LIEF::DEX::py {

template<>
void create<Prototype>(nb::module_& m) {
  using namespace LIEF::py;

  nb::class_<Prototype, LIEF::Object> proto(m, "Prototype",
      "DEX Prototype representation"_doc);

  init_ref_iterator<Prototype::it_params>(proto, "it_params");

  proto
    .def_prop_ro("return_type",
        nb::overload_cast<>(&Prototype::return_type, nb::const_),
        "" RST_CLASS_REF(lief.DEX.Type) " returned"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("parameters_type",
        nb::overload_cast<>(&Prototype::parameters_type),
        "Iterator over parameters  " RST_CLASS_REF(lief.DEX.Type) ""_doc)

    LIEF_DEFAULT_STR(Prototype);
}
}
