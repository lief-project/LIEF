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
#include "LIEF/PE/ExceptionInfo.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

namespace LIEF::PE {
class RuntimeFunctionX64;
class RuntimeFunctionAArch64;
}

namespace LIEF::PE::py {

template<>
void create<ExceptionInfo>(nb::module_& m) {

  nb::class_<ExceptionInfo> exception(m, "ExceptionInfo",
    "This class is the base class for any exception or runtime function entry"_doc
  );

  nb::enum_<ExceptionInfo::ARCH>(exception, "ARCH",
    "Arch discriminator for the subclasses"_doc
  )
    .value("UNKNOWN", ExceptionInfo::ARCH::UNKNOWN)
    .value("ARM64", ExceptionInfo::ARCH::ARM64)
    .value("X86_64", ExceptionInfo::ARCH::X86_64)
  ;

  exception
    .def_prop_ro("arch", &ExceptionInfo::arch,
      "Target architecture of this exception"_doc
    )
    .def_prop_ro("rva_start", &ExceptionInfo::rva_start,
      "Function start address"_doc
    )
    LIEF_CLONABLE(ExceptionInfo)
    LIEF_DEFAULT_STR(ExceptionInfo);

  create<RuntimeFunctionX64>(m);
  create<RuntimeFunctionAArch64>(m);
}

}
