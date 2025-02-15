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
#include "LIEF/PE/debug/VCFeature.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/extra/memoryview.hpp>
#include "nanobind/utils.hpp"

namespace LIEF::PE::py {

template<>
void create<VCFeature>(nb::module_& m) {
  nb::class_<VCFeature, Debug>(m, "VCFeature",
    R"delim(
    This class represents the ``IMAGE_DEBUG_TYPE_VC_FEATURE`` debug entry
    )delim"_doc)
    .def_prop_rw("pre_vcpp",
      nb::overload_cast<>(&VCFeature::pre_vcpp, nb::const_),
      nb::overload_cast<uint32_t>(&VCFeature::pre_vcpp),
      "Count for ``Pre-VC++ 11.00``"_doc, nb::rv_policy::reference_internal
    )
    .def_prop_rw("c_cpp",
      nb::overload_cast<>(&VCFeature::c_cpp, nb::const_),
      nb::overload_cast<uint32_t>(&VCFeature::c_cpp),
      "Count for ``C/C++``"_doc,
      nb::rv_policy::reference_internal
    )
    .def_prop_rw("gs",
      nb::overload_cast<>(&VCFeature::gs, nb::const_),
      nb::overload_cast<uint32_t>(&VCFeature::gs),
      "Count for ``/GS`` (number of guard stack)"_doc,
      nb::rv_policy::reference_internal
    )
    .def_prop_rw("sdl",
      nb::overload_cast<>(&VCFeature::sdl, nb::const_),
      nb::overload_cast<uint32_t>(&VCFeature::sdl),
      R"doc(
      Whether ``/sdl`` was enabled for this binary.

      ``sdl`` stands for Security Development Lifecycle and provides enhanced
      security features like changing security-relevant warnings into errors or
      enforcing guard stack.
      )doc"_doc,
      nb::rv_policy::reference_internal
    )
    .def_prop_rw("guards",
      nb::overload_cast<>(&VCFeature::guards, nb::const_),
      nb::overload_cast<uint32_t>(&VCFeature::guards),
      "Count for ``/guardN``"_doc,
      nb::rv_policy::reference_internal
    )
  ;

}
}
