/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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

#include "pyErr.hpp"
#include "LIEF/PE/Factory.hpp"
#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/LoadConfigurations.hpp"
#include "LIEF/PE/TLS.hpp"
#include "LIEF/PE/RichHeader.hpp"
#include "LIEF/PE/ResourceNode.hpp"
#include "LIEF/PE/Export.hpp"
#include "LIEF/PE/Debug.hpp"
#include "LIEF/PE/Relocation.hpp"
#include "LIEF/PE/RelocationEntry.hpp"
#include "LIEF/PE/Section.hpp"

#include <string>
#include <sstream>
#include "nanobind/utils.hpp"
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/function.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::PE::py {

template<>
void create<Factory>(nb::module_& m) {
  using namespace LIEF::py;
  nb::class_<Factory> factory(m, "Factory");

  factory
    .def_static("create", &Factory::create)
    .def("add_section", &Factory::add_section,
         nb::rv_policy::reference)
    .def("get", &Factory::get)
  ;

}
}
