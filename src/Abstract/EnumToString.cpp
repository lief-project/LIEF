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
#include "LIEF/Abstract/EnumToString.hpp"
#include "frozen.hpp"

namespace LIEF {


const char* to_string(OBJECT_TYPES e) {
  CONST_MAP(OBJECT_TYPES, const char*, 4) enumStrings {
    { OBJECT_TYPES::TYPE_NONE,       "NONE"       },
    { OBJECT_TYPES::TYPE_EXECUTABLE, "EXECUTABLE" },
    { OBJECT_TYPES::TYPE_LIBRARY,    "LIBRARY"    },
    { OBJECT_TYPES::TYPE_OBJECT,     "OBJECT"     },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(ARCHITECTURES e) {
  CONST_MAP(ARCHITECTURES, const char*, 12) enumStrings {
    { ARCHITECTURES::ARCH_NONE,  "NONE"  },
    { ARCHITECTURES::ARCH_ARM,   "ARM"   },
    { ARCHITECTURES::ARCH_ARM64, "ARM64" },
    { ARCHITECTURES::ARCH_MIPS,  "MIPS"  },
    { ARCHITECTURES::ARCH_X86,   "X86"    },
    { ARCHITECTURES::ARCH_PPC,   "PPC"   },
    { ARCHITECTURES::ARCH_SPARC, "SPARC" },
    { ARCHITECTURES::ARCH_SYSZ,  "SYSZ"  },
    { ARCHITECTURES::ARCH_XCORE, "XCORE" },
    { ARCHITECTURES::ARCH_INTEL, "INTEL" },
    { ARCHITECTURES::ARCH_RISCV, "RISCV" },
    { ARCHITECTURES::ARCH_LOONGARCH, "LOONGARCH" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}


const char* to_string(MODES e) {
  CONST_MAP(MODES, const char*, 15) enumStrings {
    { MODES::MODE_NONE,          "NONE"  },
    { MODES::MODE_16,            "M16"  },
    { MODES::MODE_32,            "M32"    },
    { MODES::MODE_64,            "M64"   },
    { MODES::MODE_ARM,           "ARM" },
    { MODES::MODE_THUMB,         "THUMB"  },
    { MODES::MODE_MCLASS,        "MCLASS" },
    { MODES::MODE_MIPS3,         "MIPS3" },
    { MODES::MODE_MIPS32R6,      "MIPS32R6" },
    { MODES::MODE_MIPSGP64,      "MIPSGP64" },
    { MODES::MODE_V7,            "V7" },
    { MODES::MODE_V8,            "V8" },
    { MODES::MODE_V9,            "V9" },
    { MODES::MODE_MIPS32,        "MIPS32" },
    { MODES::MODE_MIPS64,        "MIPS64" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(ENDIANNESS e) {
  CONST_MAP(ENDIANNESS, const char*, 3) enumStrings {
    { ENDIANNESS::ENDIAN_NONE,   "NONE"   },
    { ENDIANNESS::ENDIAN_BIG,    "BIG"    },
    { ENDIANNESS::ENDIAN_LITTLE, "LITTLE" },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}

const char* to_string(Function::FLAGS e) {
  CONST_MAP(Function::FLAGS, const char*, 5) enumStrings {
    { LIEF::Function::FLAGS::DEBUG_INFO,   "DEBUG_INFO"   },
    { LIEF::Function::FLAGS::CONSTRUCTOR,  "CONSTRUCTOR"  },
    { LIEF::Function::FLAGS::DESTRUCTOR,   "DESTRUCTOR"   },
    { LIEF::Function::FLAGS::IMPORTED,     "IMPORTED"     },
    { LIEF::Function::FLAGS::EXPORTED,     "EXPORTED"     },
  };
  const auto it = enumStrings.find(e);
  return it == enumStrings.end() ? "UNDEFINED" : it->second;
}




} // namespace LIEF



