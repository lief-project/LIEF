/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#ifndef LIEF_ELF_RELOC_UTILS_H
#define LIEF_ELF_RELOC_UTILS_H
#include <cstdint>

#include "LIEF/ELF/enums.hpp"
#include "LIEF/ELF/Header.hpp"

// Internal helpers for the MIPS n64 relocation encoding only.
//
// ELFCLASS64 + EM_MIPS files (n64/o64/eabi64) pack r_info on disk as
// r_sym[4] | r_ssym | r_type3 | r_type2 | r_type instead of the generic
// Elf64 r_info (sym in the high 32 bits, type in the low 32). binutils handles
// this in elf64-mips.c (mips_elf64_swap_reloc_in); the layout is selected by
// EI_CLASS == ELFCLASS64 (binutils ABI_64_P), which is what the callers check.
//
// LIEF reads the 8-byte r_info as a single host-order integer (the stream has
// already applied the endianness swap), so within this MIPS packing the field
// positions depend on the file endianness. These helpers isolate that detail so
// the generic Relocation class and the non-MIPS decode paths stay untouched.
namespace LIEF::ELF::reloc_utils {

/// True for a MIPS n64 (ELF64) file, whose on-disk relocations use the
/// MIPS-specific packing. This is the same condition binutils uses
/// (ABI_64_P: elfclass == ELFCLASS64); it excludes n32/o32, which are
/// ELFCLASS32 and use the standard Elf32_Rel.
inline bool is_mips_n64(ARCH arch, Header::CLASS clazz) {
  return arch == ARCH::MIPS && clazz == Header::CLASS::ELF64;
}

struct DecodedMipsN64 {
  uint32_t type_value;
  uint32_t sym_idx;
};

/// Decode the MIPS n64 on-disk r_info packing. The caller must have already
/// established this is a MIPS n64 entry (see is_mips_n64).
inline DecodedMipsN64 decode_mips_n64(uint64_t r_info, Header::ELF_DATA data) {
  if (data == Header::ELF_DATA::LSB) {
    // little-endian: r_sym in the low 32 bits, r_type in the high byte
    return {static_cast<uint32_t>(r_info >> 56),
            static_cast<uint32_t>(r_info & 0xffffffff)};
  }
  // big-endian: r_sym in the high 32 bits, r_type in the low byte
  return {static_cast<uint32_t>(r_info & 0xff),
          static_cast<uint32_t>(r_info >> 32)};
}

/// Inverse of decode_mips_n64: pack {type, symbol index} back into the MIPS
/// n64 on-disk r_info.
inline uint64_t encode_mips_n64(uint32_t type_value, uint32_t sym_idx,
                                Header::ELF_DATA data) {
  if (data == Header::ELF_DATA::LSB) {
    return (uint64_t(type_value & 0xff) << 56) | uint64_t(sym_idx);
  }
  return (uint64_t(sym_idx) << 32) | (type_value & 0xff);
}

} // namespace LIEF::ELF::reloc_utils

#endif
