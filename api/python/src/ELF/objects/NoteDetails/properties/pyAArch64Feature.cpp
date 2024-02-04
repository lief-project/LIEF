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
#include <string>
#include <sstream>

#include <nanobind/stl/vector.h>

#include "enums_wrapper.hpp"
#include "ELF/pyELF.hpp"

#include "LIEF/ELF/NoteDetails/properties/AArch64Feature.hpp"

namespace LIEF::ELF::py {

template<>
void create<AArch64Feature>(nb::module_& m) {
  nb::class_<AArch64Feature, NoteGnuProperty::Property>
    Class(m, "AArch64Feature",
      R"doc(
      This class represents the `GNU_PROPERTY_AARCH64_FEATURE_1_AND` note.
      )doc"_doc);

  Class
    .def_prop_ro("features", &AArch64Feature::features,
        R"doc(
        Return the list of the supported features.
        )doc"_doc);

# define ENTRY(X, D) .value(to_string(AArch64Feature::FEATURE::X), AArch64Feature::FEATURE::X, D)
  enum_<AArch64Feature::FEATURE>(Class, "FEATURE")
    ENTRY(UNKNOWN, "")
    ENTRY(BTI, "Support Branch Target Identification (BTI)")
    ENTRY(PAC, "Support Pointer authentication (PAC)")
  ;
# undef ENTRY
}

}
