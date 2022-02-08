/* Copyright 2021 - 2022 R. Thomas
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
// From llvm/Support/MachO.h - The MachO file format
#ifndef LIEF_MACHO_STRUCTURES_H_
#define LIEF_MACHO_STRUCTURES_H_

#include <cstdint>
#include <string>

#include "LIEF/types.hpp"

#include "LIEF/MachO/enums.hpp"


// Swap 2 byte, 16 bit values:
#define Swap2Bytes(val) \
 ( (((val) >> 8) & 0x00FF) | (((val) << 8) & 0xFF00) )


// Swap 4 byte, 32 bit values:
#define Swap4Bytes(val) \
 ( (((val) >> 24) & 0x000000FF) | (((val) >>  8) & 0x0000FF00) | \
   (((val) <<  8) & 0x00FF0000) | (((val) << 24) & 0xFF000000) )



// Swap 8 byte, 64 bit values:
#define Swap8Bytes(val) \
 ( (((val) >> 56) & 0x00000000000000FF) | (((val) >> 40) & 0x000000000000FF00) | \
   (((val) >> 24) & 0x0000000000FF0000) | (((val) >>  8) & 0x00000000FF000000) | \
   (((val) <<  8) & 0x000000FF00000000) | (((val) << 24) & 0x0000FF0000000000) | \
   (((val) << 40) & 0x00FF000000000000) | (((val) << 56) & 0xFF00000000000000) )

namespace LIEF {
//! Namespace related to the LIEF's MachO module
namespace MachO {

namespace details {

#include "structures.inc"

struct rebase_instruction {
  rebase_instruction(uint8_t opcode, uint64_t op1, uint64_t op2 = 0) :
    opcode{opcode},
    op1{op1},
    op2{op2}
  {}

  uint8_t opcode;
  uint64_t op1;
  uint64_t op2;
};

struct binding_instruction {
  binding_instruction(uint8_t opcode, uint64_t op1, uint64_t op2 = 0, std::string name = "") :
    opcode{opcode},
    op1{op1},
    op2{op2},
    name{name}
  {}
  binding_instruction(const binding_instruction&) = default;
  binding_instruction& operator=(const binding_instruction&) = default;


  uint8_t opcode;
  uint64_t op1;
  uint64_t op2;
  std::string name;
};


class MachO32 {
  public:
  using header                  = mach_header;
  using segment_command         = segment_command_32;
  using section                 = section_32;
  using routines_command        = routines_command_32;
  using dylib_module            = dylib_module_32;
  using nlist                   = nlist_32;

  using uint                    = uint32_t;
};

class MachO64 {
  public:
  using header                  = mach_header_64;
  using segment_command         = segment_command_64;
  using section                 = section_64;
  using routines_command        = routines_command_64;
  using dylib_module            = dylib_module_64;
  using nlist                   = nlist_64;

  using uint                    = uint64_t;
};
}
} // end namespace MachO
}
#endif
