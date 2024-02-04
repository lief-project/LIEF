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
#include "ELF/pyELF.hpp"

#include "LIEF/ELF/NoteDetails/properties/Generic.hpp"

namespace LIEF::ELF::py {

template<>
void create<Generic>(nb::module_& m) {
  nb::class_<Generic, NoteGnuProperty::Property>(m, "Generic",
      R"doc(
      This class represents a property which doesn't have a concrete LIEF implementation.
      )doc")
    .def_prop_ro("raw_type", &Generic::type,
        R"doc(
        The original raw type as an integer. This value might depends
        on the architecture and/or the file type.
        )doc");

}

}
