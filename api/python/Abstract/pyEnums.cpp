/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include "pyAbstract.hpp"
#include "LIEF/Abstract/enums.hpp"
#include "LIEF/Abstract/EnumToString.hpp"

#define PY_ENUM(x) LIEF::to_string(x), x
namespace LIEF {

void init_enums(py::module& m) {
  py::enum_<EXE_FORMATS>(m, "EXE_FORMATS")
    .value(PY_ENUM(EXE_FORMATS::FORMAT_UNKNOWN))
    .value(PY_ENUM(EXE_FORMATS::FORMAT_ELF))
    .value(PY_ENUM(EXE_FORMATS::FORMAT_PE))
    .value(PY_ENUM(EXE_FORMATS::FORMAT_MACHO));

  py::enum_<OBJECT_TYPES>(m, "OBJECT_TYPES")
    .value(PY_ENUM(OBJECT_TYPES::TYPE_NONE))
    .value(PY_ENUM(OBJECT_TYPES::TYPE_EXECUTABLE))
    .value(PY_ENUM(OBJECT_TYPES::TYPE_LIBRARY))
    .value(PY_ENUM(OBJECT_TYPES::TYPE_OBJECT));

  py::enum_<ARCHITECTURES>(m, "ARCHITECTURES")
    .value(PY_ENUM(ARCHITECTURES::ARCH_NONE))
    .value(PY_ENUM(ARCHITECTURES::ARCH_ARM))
    .value(PY_ENUM(ARCHITECTURES::ARCH_ARM64))
    .value(PY_ENUM(ARCHITECTURES::ARCH_MIPS))
    .value(PY_ENUM(ARCHITECTURES::ARCH_X86))
    .value(PY_ENUM(ARCHITECTURES::ARCH_PPC))
    .value(PY_ENUM(ARCHITECTURES::ARCH_SPARC))
    .value(PY_ENUM(ARCHITECTURES::ARCH_SYSZ))
    .value(PY_ENUM(ARCHITECTURES::ARCH_XCORE))
    .value(PY_ENUM(ARCHITECTURES::ARCH_INTEL))
    .value(PY_ENUM(ARCHITECTURES::ARCH_RISCV));

  py::enum_<MODES>(m, "MODES")
    .value(PY_ENUM(MODES::MODE_NONE))
    .value(PY_ENUM(MODES::MODE_16))
    .value(PY_ENUM(MODES::MODE_32))
    .value(PY_ENUM(MODES::MODE_64))
    .value(PY_ENUM(MODES::MODE_ARM))
    .value(PY_ENUM(MODES::MODE_THUMB))
    .value(PY_ENUM(MODES::MODE_MCLASS))
    .value(PY_ENUM(MODES::MODE_MICRO))
    .value(PY_ENUM(MODES::MODE_MIPS3))
    .value(PY_ENUM(MODES::MODE_MIPS32R6))
    .value(PY_ENUM(MODES::MODE_MIPSGP64))
    .value(PY_ENUM(MODES::MODE_V7))
    .value(PY_ENUM(MODES::MODE_V8))
    .value(PY_ENUM(MODES::MODE_V9))
    .value(PY_ENUM(MODES::MODE_MIPS32))
    .value(PY_ENUM(MODES::MODE_MIPS64));

  py::enum_<ENDIANNESS>(m, "ENDIANNESS")
    .value(PY_ENUM(ENDIANNESS::ENDIAN_NONE))
    .value(PY_ENUM(ENDIANNESS::ENDIAN_BIG))
    .value(PY_ENUM(ENDIANNESS::ENDIAN_LITTLE));
}
}
