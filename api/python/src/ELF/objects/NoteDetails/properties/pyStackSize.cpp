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

#include "LIEF/ELF/NoteDetails/properties/StackSize.hpp"

namespace LIEF::ELF::py {

template<>
void create<StackSize>(nb::module_& m) {
  nb::class_<StackSize, NoteGnuProperty::Property>(m, "StackSize",
    R"doc(
    This class provides an interface over the `GNU_PROPERTY_STACK_SIZE` property
    This property can be used by the loader to raise the stack limit.
    )doc")
    .def_prop_ro("stack_size", &StackSize::stack_size);

}

}
