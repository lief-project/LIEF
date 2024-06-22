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
#include <nanobind/stl/string.h>

#include "ELF/pyELF.hpp"

#include "LIEF/ELF/NoteDetails/QNXStack.hpp"

namespace LIEF::ELF::py {

template<>
void create<QNXStack>(nb::module_& m) {
  nb::class_<QNXStack, Note>(m, "QNXStack")
    .def_prop_rw("stack_size",
        nb::overload_cast<>(&QNXStack::stack_size, nb::const_),
        nb::overload_cast<uint32_t>(&QNXStack::stack_size),
        "Size of the stack"_doc)

    .def_prop_rw("stack_allocated",
        nb::overload_cast<>(&QNXStack::stack_allocated, nb::const_),
        nb::overload_cast<uint32_t>(&QNXStack::stack_allocated),
        "Size of the stack pre-allocated (upfront)"_doc)

    .def_prop_rw("is_executable",
        nb::overload_cast<>(&QNXStack::is_executable, nb::const_),
        nb::overload_cast<bool>(&QNXStack::set_is_executable),
        "Whether the stack is executable"_doc)

    LIEF_DEFAULT_STR(QNXStack);
}

}
