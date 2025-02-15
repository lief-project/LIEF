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
#include "LIEF/PE/exceptions_info/AArch64/PackedFunction.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>


namespace LIEF::PE::py {

using namespace unwind_aarch64;

template<>
void create<PackedFunction>(nb::module_& m) {
  nb::class_<PackedFunction, RuntimeFunctionAArch64>(m, "PackedFunction",
    R"doc(
    This class represents a packed AArch64 exception entry.

    An exception entry can be packed if the unwind data fit in 30 bits

    Reference: https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling?view=msvc-170#packed-unwind-data
    )doc"_doc)

    .def_prop_rw("frame_size",
      nb::overload_cast<>(&PackedFunction::frame_size, nb::const_),
      nb::overload_cast<uint8_t>(&PackedFunction::frame_size),
      "Size of the allocated stack"_doc)

    .def_prop_rw("reg_I",
      nb::overload_cast<>(&PackedFunction::reg_I, nb::const_),
      nb::overload_cast<uint8_t>(&PackedFunction::reg_I),
      R"doc(
      Number of non-volatile INT registers (x19-x28) saved in the canonical
      stack location.
      )doc"_doc
    )

    .def_prop_rw("reg_F",
      nb::overload_cast<>(&PackedFunction::reg_F, nb::const_),
      nb::overload_cast<uint8_t>(&PackedFunction::reg_F),
      R"doc(
      Number of non-volatile FP registers (d8-d15) saved in the canonical stack
      location
      )doc"_doc
    )

    .def_prop_rw("H",
      nb::overload_cast<>(&PackedFunction::H, nb::const_),
      nb::overload_cast<uint8_t>(&PackedFunction::H),
      R"doc(
      1-bit flag indicating whether the function homes the integer parameter
      registers (x0-x7) by storing them at the very start of the function.
      (0 = doesn't home registers, 1 = homes registers).
      )doc"_doc
    )

    .def_prop_rw("CR",
      nb::overload_cast<>(&PackedFunction::CR, nb::const_),
      nb::overload_cast<uint8_t>(&PackedFunction::CR),
      R"doc(
      Flag indicating whether the function includes extra instructions to set
      up a frame chain and return link.
      )doc"_doc
    );
}

}
