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
#ifndef C_LIEF_PE_HEADER_H
#define C_LIEF_PE_HEADER_H

#include <inttypes.h>

#include "LIEF/visibility.h"

#ifdef __cplusplus
extern "C" {
#endif

enum LIEF_PE_MACHINE_TYPES {
  LIEF_PE_MACHINE_UNKNOWN   = 0x0,
  LIEF_PE_MACHINE_AM33      = 0x1D3,  /**< Matsushita AM33                */
  LIEF_PE_MACHINE_AMD64     = 0x8664, /**< AMD x64                        */
  LIEF_PE_MACHINE_ARM       = 0x1C0,  /**< ARM little endian              */
  LIEF_PE_MACHINE_ARMNT     = 0x1C4,  /**< ARMv7 Thumb mode only          */
  LIEF_PE_MACHINE_ARM64     = 0xAA64, /**< ARMv8 in 64-bits mode          */
  LIEF_PE_MACHINE_EBC       = 0xEBC,  /**< EFI byte code                  */
  LIEF_PE_MACHINE_I386      = 0x14C,  /**< Intel 386 or later             */
  LIEF_PE_MACHINE_IA64      = 0x200,  /**< Intel Itanium processor family */
  LIEF_PE_MACHINE_M32R      = 0x9041, /**< Mitsubishi M32R little endian  */
  LIEF_PE_MACHINE_MIPS16    = 0x266,  /**< MIPS16                         */
  LIEF_PE_MACHINE_MIPSFPU   = 0x366,  /**< MIPS with FPU                  */
  LIEF_PE_MACHINE_MIPSFPU16 = 0x466,  /**< MIPS16 with FPU                */
  LIEF_PE_MACHINE_POWERPC   = 0x1F0,  /**< Power PC little endian         */
  LIEF_PE_MACHINE_POWERPCFP = 0x1F1,  /**< Power PC with floating point   */
  LIEF_PE_MACHINE_R4000     = 0x166,  /**< MIPS with little endian        */
  LIEF_PE_MACHINE_RISCV32   = 0x5032, /**< RISC-V 32-bit address space    */
  LIEF_PE_MACHINE_RISCV64   = 0x5064, /**< RISC-V 64-bit address space    */
  LIEF_PE_MACHINE_RISCV128  = 0x5128, /**< RISC-V 128-bit address space   */
  LIEF_PE_MACHINE_SH3       = 0x1A2,  /**< Hitachi SH3                    */
  LIEF_PE_MACHINE_SH3DSP    = 0x1A3,  /**< Hitachi SH3 DSP                */
  LIEF_PE_MACHINE_SH4       = 0x1A6,  /**< Hitachi SH4                    */
  LIEF_PE_MACHINE_SH5       = 0x1A8,  /**< Hitachi SH5                    */
  LIEF_PE_MACHINE_THUMB     = 0x1C2,  /**< ARM or Thumb                   */
  LIEF_PE_MACHINE_WCEMIPSV2 = 0x169   /**< MIPS little-endian WCE v2      */
};

enum LIEF_PE_HEADER_CHARACTERISTICS {
  LIEF_PE_HEADER_CHARACTERISTICS_INVALID                 = 0x0000,
  LIEF_PE_HEADER_CHARACTERISTICS_RELOCS_STRIPPED         = 0x0001, /**< The file does not contain base relocations and must be loaded at its preferred base. If this cannot be done, the loader will error.*/
  LIEF_PE_HEADER_CHARACTERISTICS_EXECUTABLE_IMAGE        = 0x0002, /**< The file is valid and can be run.*/
  LIEF_PE_HEADER_CHARACTERISTICS_LINE_NUMS_STRIPPED      = 0x0004, /**< COFF line numbers have been stripped. This is deprecated and should be 0*/
  LIEF_PE_HEADER_CHARACTERISTICS_LOCAL_SYMS_STRIPPED     = 0x0008, /**< COFF symbol table entries for local symbols have been removed. This is deprecated and should be 0.*/
  LIEF_PE_HEADER_CHARACTERISTICS_AGGRESSIVE_WS_TRIM      = 0x0010, /**< Aggressively trim working set. This is deprecated and must be 0.*/
  LIEF_PE_HEADER_CHARACTERISTICS_LARGE_ADDRESS_AWARE     = 0x0020, /**< Image can handle > 2GiB addresses. */
  LIEF_PE_HEADER_CHARACTERISTICS_BYTES_REVERSED_LO       = 0x0080, /**< Little endian: the LSB precedes the MSB in memory. This is deprecated and should be 0.*/
  LIEF_PE_HEADER_CHARACTERISTICS_32BIT_MACHINE           = 0x0100, /**< Machine is based on a 32bit word architecture. */
  LIEF_PE_HEADER_CHARACTERISTICS_DEBUG_STRIPPED          = 0x0200, /**< Debugging info has been removed. */
  LIEF_PE_HEADER_CHARACTERISTICS_REMOVABLE_RUN_FROM_SWAP = 0x0400, /**< If the image is on removable media, fully load it and copy it to swap. */
  LIEF_PE_HEADER_CHARACTERISTICS_NET_RUN_FROM_SWAP       = 0x0800, /**< If the image is on network media, fully load it and copy it to swap. */
  LIEF_PE_HEADER_CHARACTERISTICS_SYSTEM                  = 0x1000, /**< The image file is a system file, not a user program.*/
  LIEF_PE_HEADER_CHARACTERISTICS_DLL                     = 0x2000, /**< The image file is a DLL. */
  LIEF_PE_HEADER_CHARACTERISTICS_UP_SYSTEM_ONLY          = 0x4000, /**< This file should only be run on a uniprocessor machine. */
  LIEF_PE_HEADER_CHARACTERISTICS_BYTES_REVERSED_HI       = 0x8000  /**< Big endian: the MSB precedes the LSB in memory. This is deprecated */
};

struct Pe_Header_t {
  uint8_t            signature[4];
  enum LIEF_PE_MACHINE_TYPES machine;
  uint16_t           numberof_sections;
  uint32_t           time_date_stamp;
  uint32_t           pointerto_symbol_table;
  uint32_t           numberof_symbols;
  uint16_t           sizeof_optional_header;
  uint16_t           characteristics;
};

typedef struct Pe_Header_t Pe_Header_t;

LIEF_API const char* lief_pe_header_machine_str(enum LIEF_PE_MACHINE_TYPES e);
LIEF_API const char* lief_pe_header_characteristics_str(enum LIEF_PE_HEADER_CHARACTERISTICS e);

#ifdef __cplusplus
}
#endif

#endif
