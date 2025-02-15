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
#include "LIEF/PE/exceptions_info/RuntimeFunctionAArch64.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::unwind_aarch64 {
class PackedFunction;
class UnpackedFunction;
}

namespace LIEF::PE::py {

template<>
void create<RuntimeFunctionAArch64>(nb::module_& m) {
  nb::class_<RuntimeFunctionAArch64, ExceptionInfo> rfunc(m, "RuntimeFunctionAArch64",
    R"doc(
    This class represents an entry in the exception table (``.pdata`` section)
    for the AArch64 architecture.

    Since the ARM64 unwinding info can be encoded in a *packed* and *unpacked*
    format, this class is inherited by :class:`lief.PE.unwind_aarch64.PackedFunction`
    and :class:`lief.pe.unwind_aarch64.UnpackedFunction`

    Reference: https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling#arm64-exception-handling-information
    )doc"_doc);

  using PACKED_FLAGS = RuntimeFunctionAArch64::PACKED_FLAGS;
  nb::enum_<PACKED_FLAGS>(rfunc, "PACKED_FLAGS")
    .value("UNPACKED", PACKED_FLAGS::UNPACKED)
    .value("PACKED", PACKED_FLAGS::PACKED)
    .value("PACKED_FRAGMENT", PACKED_FLAGS::PACKED_FRAGMENT)
    .value("RESERVED", PACKED_FLAGS::RESERVED);

  rfunc
    .def_prop_ro("length", &RuntimeFunctionAArch64::length,
                 "Length of the function in bytes"_doc)

    .def_prop_ro("flag", &RuntimeFunctionAArch64::flag,
                 "Flag describing the format the unwind data"_doc)

    .def_prop_ro("rva_end", &RuntimeFunctionAArch64::rva_end,
                 "Function end address"_doc)
  ;

  nb::module_ submod = m.def_submodule("unwind_aarch64",
    "Module related to PE-ARM64 unwinding code"_doc
  );
  create<unwind_aarch64::UnpackedFunction>(submod);
  create<unwind_aarch64::PackedFunction>(submod);

}

}
