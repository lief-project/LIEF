/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#include "init.hpp"
#include "LIEF/Abstract/enums.hpp"
#include "LIEF/Abstract/EnumToString.hpp"

#define PY_ENUM(x) LIEF::to_string(x), x

void init_LIEF_Enum(py::module& m) {
  py::enum_<LIEF::EXE_FORMATS>(m, "EXE_FORMATS")
    .value(PY_ENUM(LIEF::EXE_FORMATS::FORMAT_UNKNOWN))
    .value(PY_ENUM(LIEF::EXE_FORMATS::FORMAT_ELF))
    .value(PY_ENUM(LIEF::EXE_FORMATS::FORMAT_PE))
    .value(PY_ENUM(LIEF::EXE_FORMATS::FORMAT_MACHO))
    .export_values();

  py::enum_<LIEF::OBJECT_TYPES>(m, "OBJECT_TYPES")
    .value(PY_ENUM(LIEF::OBJECT_TYPES::TYPE_NONE))
    .value(PY_ENUM(LIEF::OBJECT_TYPES::TYPE_EXECUTABLE))
    .value(PY_ENUM(LIEF::OBJECT_TYPES::TYPE_LIBRARY))
    .value(PY_ENUM(LIEF::OBJECT_TYPES::TYPE_OBJECT))
    .export_values();

  py::enum_<LIEF::ARCHITECTURES>(m, "ARCHITECTURES")
    .value(PY_ENUM(LIEF::ARCHITECTURES::ARCH_NONE))
    .value(PY_ENUM(LIEF::ARCHITECTURES::ARCH_ARM))
    .value(PY_ENUM(LIEF::ARCHITECTURES::ARCH_ARM64))
    .value(PY_ENUM(LIEF::ARCHITECTURES::ARCH_MIPS))
    .value(PY_ENUM(LIEF::ARCHITECTURES::ARCH_X86))
    .value(PY_ENUM(LIEF::ARCHITECTURES::ARCH_PPC))
    .value(PY_ENUM(LIEF::ARCHITECTURES::ARCH_SPARC))
    .value(PY_ENUM(LIEF::ARCHITECTURES::ARCH_SYSZ))
    .value(PY_ENUM(LIEF::ARCHITECTURES::ARCH_XCORE))
    .value(PY_ENUM(LIEF::ARCHITECTURES::ARCH_INTEL))
    .export_values();

  py::enum_<LIEF::MODES>(m, "MODES")
    .value(PY_ENUM(LIEF::MODES::MODE_NONE))
    .value(PY_ENUM(LIEF::MODES::MODE_16))
    .value(PY_ENUM(LIEF::MODES::MODE_32))
    .value(PY_ENUM(LIEF::MODES::MODE_64))
    .value(PY_ENUM(LIEF::MODES::MODE_ARM))
    .value(PY_ENUM(LIEF::MODES::MODE_THUMB))
    .value(PY_ENUM(LIEF::MODES::MODE_MCLASS))
    .value(PY_ENUM(LIEF::MODES::MODE_MICRO))
    .value(PY_ENUM(LIEF::MODES::MODE_MIPS3))
    .value(PY_ENUM(LIEF::MODES::MODE_MIPS32R6))
    .value(PY_ENUM(LIEF::MODES::MODE_MIPSGP64))
    .value(PY_ENUM(LIEF::MODES::MODE_V7))
    .value(PY_ENUM(LIEF::MODES::MODE_V8))
    .value(PY_ENUM(LIEF::MODES::MODE_V9))
    .value(PY_ENUM(LIEF::MODES::MODE_MIPS32))
    .value(PY_ENUM(LIEF::MODES::MODE_MIPS64))
    .export_values();

  py::enum_<LIEF::ENDIANNESS>(m, "ENDIANNESS")
    .value(PY_ENUM(LIEF::ENDIANNESS::ENDIAN_NONE))
    .value(PY_ENUM(LIEF::ENDIANNESS::ENDIAN_BIG))
    .value(PY_ENUM(LIEF::ENDIANNESS::ENDIAN_LITTLE))
    .export_values();
}
