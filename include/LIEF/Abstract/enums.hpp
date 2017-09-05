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
#ifndef LIEF_ABSTRACT_ENUMS_H_
#define LIEF_ABSTRACT_ENUMS_H_

#include "LIEF/types.hpp"

namespace LIEF {

enum EXE_FORMATS {
  FORMAT_UNKNOWN = 0,
  FORMAT_ELF     = 1,
  FORMAT_PE      = 2,
  FORMAT_MACHO   = 3,
};

enum OBJECT_TYPES {
  TYPE_NONE       = 0,
  TYPE_EXECUTABLE = 1,
  TYPE_LIBRARY    = 2,
  TYPE_OBJECT     = 3,
};

// Inspired from capstone
enum ARCHITECTURES {
  ARCH_NONE  = 0,
  ARCH_ARM   = 1,
  ARCH_ARM64 = 2,
  ARCH_MIPS  = 3,
  ARCH_X86   = 4,
  ARCH_PPC   = 5,
  ARCH_SPARC = 6,
  ARCH_SYSZ  = 7,
  ARCH_XCORE = 8,
  ARCH_INTEL = 9,
};

enum MODES {
  MODE_NONE          = 0,
  MODE_16            = 1,
  MODE_32            = 2,
  MODE_64            = 3,
  MODE_ARM           = 4,
  MODE_THUMB         = 5,
  MODE_MCLASS        = 6,
  MODE_MICRO         = 7,
  MODE_MIPS3         = 8,
  MODE_MIPS32R6      = 9,
  MODE_MIPSGP64      = 10,
  MODE_V7            = 11,
  MODE_V8            = 12,
  MODE_V9            = 13,
  MODE_MIPS32        = 14,
  MODE_MIPS64        = 15,
};

enum ENDIANNESS {
  ENDIAN_NONE   = 0,
  ENDIAN_BIG    = 1,
  ENDIAN_LITTLE = 2,
};





} // namespace LIEF
#endif
