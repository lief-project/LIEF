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
#include "easylogging++.h"

namespace LIEF {
namespace ELF {

template<>
void Binary::patch_relocations<ARCH::EM_ARM>(uint64_t from, uint64_t shift) {
  for (Relocation& relocation : this->get_relocations()) {

    if (relocation.address() >= from) {
      relocation.address(relocation.address() + shift);
    }

    switch (relocation.type()) {
      case RELOC_ARM::R_ARM_JUMP_SLOT:
      case RELOC_ARM::R_ARM_RELATIVE:
      case RELOC_ARM::R_ARM_GLOB_DAT:
      case RELOC_ARM::R_ARM_IRELATIVE:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint32_t>(relocation, from, shift);
          break;
        }

      default:
        {
        }
    }
  }
}


template<>
void Binary::patch_relocations<ARCH::EM_AARCH64>(uint64_t from, uint64_t shift) {
  for (Relocation& relocation : this->get_relocations()) {

    if (relocation.address() >= from) {
      relocation.address(relocation.address() + shift);
    }

    switch (relocation.type()) {
      case RELOC_AARCH64::R_AARCH64_JUMP_SLOT:
      case RELOC_AARCH64::R_AARCH64_RELATIVE:
      case RELOC_AARCH64::R_AARCH64_GLOB_DAT:
      case RELOC_AARCH64::R_AARCH64_IRELATIVE:
      case RELOC_AARCH64::R_AARCH64_ABS64:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint64_t>(relocation, from, shift);
          break;
        }

      case RELOC_AARCH64::R_AARCH64_ABS32:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint32_t>(relocation, from, shift);
          break;
        }

      case RELOC_AARCH64::R_AARCH64_ABS16:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint16_t>(relocation, from, shift);
          break;
        }


      case RELOC_AARCH64::R_AARCH64_PREL64:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint64_t>(relocation, from, shift);
          break;
        }

      case RELOC_AARCH64::R_AARCH64_PREL32:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint32_t>(relocation, from, shift);
          break;
        }

      case RELOC_AARCH64::R_AARCH64_PREL16:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint16_t>(relocation, from, shift);
          break;
        }

      default:
        {
        }
    }
  }
}


template<>
void Binary::patch_relocations<ARCH::EM_386>(uint64_t from, uint64_t shift) {
  for (Relocation& relocation : this->get_relocations()) {
    if (relocation.address() >= from) {
      relocation.address(relocation.address() + shift);
    }

    switch (relocation.type()) {
      case RELOC_i386::R_386_RELATIVE:
      case RELOC_i386::R_386_JUMP_SLOT:
      case RELOC_i386::R_386_IRELATIVE:
      case RELOC_i386::R_386_GLOB_DAT:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint32_t>(relocation, from, shift);
          break;
        }

      default:
        {
        }
    }
  }
}


template<>
void Binary::patch_relocations<ARCH::EM_X86_64>(uint64_t from, uint64_t shift) {
  for (Relocation& relocation : this->get_relocations()) {
    if (relocation.address() >= from) {
      relocation.address(relocation.address() + shift);
    }

    switch (relocation.type()) {
      case RELOC_x86_64::R_X86_64_RELATIVE:
      case RELOC_x86_64::R_X86_64_IRELATIVE:
      case RELOC_x86_64::R_X86_64_JUMP_SLOT:
      case RELOC_x86_64::R_X86_64_GLOB_DAT:
      case RELOC_x86_64::R_X86_64_64:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint64_t>(relocation, from, shift);
          break;
        }

      case RELOC_x86_64::R_X86_64_32:
        {
          VLOG(VDEBUG) << "Patch addend of " << relocation;
          this->patch_addend<uint32_t>(relocation, from, shift);
          break;
        }

      default:
        {
        }
    }
  }
}


template<class T>
void Binary::patch_addend(Relocation& relocation, uint64_t from, uint64_t shift) {

  if (static_cast<uint64_t>(relocation.addend()) >= from) {
    relocation.addend(relocation.addend() + shift);
  }

  const uint64_t address = relocation.address();
  VLOG(VDEBUG) << "Patch addend relocation at address: 0x" << std::hex << address;
  Section& section = this->section_from_virtual_address(address);
  const uint64_t relative_offset = this->virtual_address_to_offset(address) - section.offset();
  std::vector<uint8_t> section_content = section.content();

  T* value = reinterpret_cast<T*>(section_content.data() + relative_offset);

  if (value != nullptr and *value >= from) {
    *value += shift;
  }

  section.content(section_content);
}

}
}
