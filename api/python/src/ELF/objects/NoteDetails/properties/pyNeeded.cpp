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
#include <string>

#include <nanobind/stl/vector.h>

#include "enums_wrapper.hpp"
#include "ELF/pyELF.hpp"

#include "LIEF/ELF/NoteDetails/properties/Needed.hpp"

namespace LIEF::ELF::py {

template<>
void create<Needed>(nb::module_& m) {
  using NEED = Needed::NEED;
  nb::class_<Needed, NoteGnuProperty::Property>
    Class(m, "Needed",
      R"doc(
      This class represents the ``GNU_PROPERTY_1_NEEDED`` note property
      which provides information about additional features the object file
      needs at runtime.
      )doc"_doc);

  enum_<NEED>(Class, "NEED")
    .value("NEED", NEED::UNKNOWN, "")
    .value("INDIRECT_EXTERN_ACCESS", NEED::INDIRECT_EXTERN_ACCESS,
           "The object needs indirect external access")
  ;

  Class
    .def_prop_ro("needs", &Needed::needs,
        R"doc(
        Return the list of the needed features.
        )doc"_doc);
}

}
