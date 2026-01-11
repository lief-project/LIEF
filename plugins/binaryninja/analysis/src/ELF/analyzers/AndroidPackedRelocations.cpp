/* Copyright 2025 - 2026 R. Thomas
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
#include "log.hpp"
#include "binaryninja/analysis/ELF/TypeBuilder.hpp"
#include "binaryninja/lief_utils.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Relocation.hpp"
#include "binaryninja/analysis/ELF/analyzers/AndroidPackedRelocations.hpp"

#include <binaryninja/binaryninjacore.h>
#include <binaryninja/binaryninjaapi.h>

#include "binaryninja/BNStream.hpp"

using namespace LIEF::ELF;
using namespace BinaryNinja;

namespace analysis_plugin::elf::analyzers {

bool AndroidPackedRelocations::can_run(BinaryNinja::BinaryView& bv, Binary& elf) {
  for (const DynamicEntry& DT : elf.dynamic_entries()) {
    switch (DT.tag()) {
      case DynamicEntry::TAG::ANDROID_REL:
      case DynamicEntry::TAG::ANDROID_RELA:
        return true;
      default:
        continue;

    }
  }
  return false;
}

void AndroidPackedRelocations::process_packed(binaryninja::BNStream& stream) {
  // This function mimics LIEF::ELF::Parser::parse_packed_relocations
  // but it defines BinaryData types while processing the stream
  static constexpr uint64_t GROUPED_BY_INFO_FLAG         = 1 << 0;
  static constexpr uint64_t GROUPED_BY_OFFSET_DELTA_FLAG = 1 << 1;
  static constexpr uint64_t GROUPED_BY_ADDEND_FLAG       = 1 << 2;
  static constexpr uint64_t GROUP_HAS_ADDEND_FLAG        = 1 << 3;

  const uint64_t start = stream.pos();

  const auto H0 = stream.read<char>().value_or(0);
  const auto H1 = stream.read<char>().value_or(0);
  const auto H2 = stream.read<char>().value_or(0);
  const auto H3 = stream.read<char>().value_or(0);

  // Check for the Magic: APS2
  if (H0 != 'A' || H1 != 'P' || H2 != 'S' || H3 != '2') {
    return;
  }

  define_array_at(start, type_builder_.char_(), 4, "format");

  uint64_t nb_relocs = 0;
  {
    const uint64_t pos = stream.pos();
    size_t size = 0;
    auto value = stream.read_sleb128(&size);
    if (!value) {
      return;
    }
    define_type_at(pos, type_builder_.sleb128(size), "nb_relocs");
    nb_relocs = *value;
  }

  uint64_t r_offset = 0;
  {
    const uint64_t pos = stream.pos();
    size_t size = 0;
    auto value = stream.read_sleb128(&size);
    if (!value) {
      return;
    }
    define_type_at(pos, type_builder_.sleb128(size), "reloc_offset");
    r_offset = *value;
  }

  uint64_t addend = 0;
  size_t leb128_size = 0;
  while (nb_relocs > 0) {
    auto nb_reloc_group_r = stream.read_sleb128(&leb128_size);
    if (!nb_reloc_group_r) {
      break;
    }

    define_type_at(stream.pos() - leb128_size,
        type_builder_.sleb128(leb128_size), "group_size");

    uint64_t nb_reloc_group = *nb_reloc_group_r;

    if (nb_reloc_group > nb_relocs) {
      break;
    }

    nb_relocs -= nb_reloc_group;

    auto group_flag_r = stream.read_sleb128(&leb128_size);
    if (!group_flag_r) {
      break;
    }

    define_type_at(stream.pos() - leb128_size,
        type_builder_.sleb128(leb128_size), "group_flags");

    uint64_t group_flag = *group_flag_r;

    const bool g_by_info         = group_flag & GROUPED_BY_INFO_FLAG;
    const bool g_by_offset_delta = group_flag & GROUPED_BY_OFFSET_DELTA_FLAG;
    const bool g_by_addend       = group_flag & GROUPED_BY_ADDEND_FLAG;
    const bool g_has_addend      = group_flag & GROUP_HAS_ADDEND_FLAG;

    uint64_t group_off_delta = 0;
    if (g_by_offset_delta) {
      if (auto value = stream.read_sleb128(&leb128_size)) {
        group_off_delta = *value;
        define_type_at(stream.pos() - leb128_size,
            type_builder_.sleb128(leb128_size), "reloc_offset");
      }
    }

    uint64_t groupr_info = 0;
    if (g_by_info) {
      if (auto value = stream.read_sleb128(&leb128_size)) {
        groupr_info = *value;

        define_type_at(stream.pos() - leb128_size,
            type_builder_.sleb128(leb128_size), "reloc_info");
      }
    }

    if (g_by_addend && g_has_addend) {
      if (auto value = stream.read_sleb128(&leb128_size)) {
        addend += *value;
        define_type_at(stream.pos() - leb128_size,
            type_builder_.sleb128(leb128_size), "reloc_addend");
      }
    }

    if (!g_has_addend) {
      addend = 0;
    }
    for (size_t i = 0; i < nb_reloc_group; ++i) {
      if (g_by_offset_delta) {
        r_offset += group_off_delta;
      } else {
        if (auto value = stream.read_sleb128(&leb128_size)) {
          r_offset += *value;
          define_type_at(stream.pos() - leb128_size,
              type_builder_.sleb128(leb128_size), fmt::format(
                "reloc_offset_{}", i));
        }
      }

      [[maybe_unused]] uint64_t info = groupr_info;
      if (!g_by_info) {
        if (auto value = stream.read_sleb128(&leb128_size)) {
          groupr_info = *value;

          define_type_at(stream.pos() - leb128_size,
              type_builder_.sleb128(leb128_size), fmt::format(
                "reloc_info_{}", i));
        }
      }

      if (g_has_addend && !g_by_addend) {
        if (auto value = stream.read_sleb128(&leb128_size)) {
          addend += *value;

          define_type_at(stream.pos() - leb128_size,
              type_builder_.sleb128(leb128_size), fmt::format(
                "reloc_addend_{}", i));
        }
      }
    }
  }
}

void AndroidPackedRelocations::process_packed(const LIEF::ELF::DynamicEntry& entry) {
  uint64_t taddr = translate_addr(entry.value());
  auto stream = binaryninja::BNStream::from_bv(bv_);
  assert(stream != nullptr);
  stream->setpos(taddr);
  process_packed(*stream);
}

void AndroidPackedRelocations::run() {
  if (DynamicEntry* dt = elf_.get(DynamicEntry::TAG::ANDROID_REL)) {
    process_packed(*dt);
  }

  if (DynamicEntry* dt = elf_.get(DynamicEntry::TAG::ANDROID_RELA)) {
    process_packed(*dt);
  }
}

}
