/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
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
#ifndef LIEF_ELF_RELOCATION_SIZES_H
#define LIEF_ELF_RELOCATION_SIZES_H

#include <cstdint>

#include "LIEF/ELF/enums.hpp"

namespace LIEF {
namespace ELF {

int32_t get_reloc_size(RELOC_x86_64 R);
int32_t get_reloc_size(RELOC_i386 R);
int32_t get_reloc_size(RELOC_ARM R);
int32_t get_reloc_size(RELOC_AARCH64 R);
int32_t get_reloc_size(RELOC_POWERPC32 R);
int32_t get_reloc_size(RELOC_POWERPC64 R);
int32_t get_reloc_size(RELOC_MIPS R);
int32_t get_reloc_size(RELOC_LOONGARCH R);

}
}

#endif
