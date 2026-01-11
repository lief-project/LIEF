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
#include "binaryninja/lief_utils.hpp"
#include "LIEF/ELF/Binary.hpp"
#include "LIEF/ELF/Relocation.hpp"
#include "binaryninja/analysis/ELF/analyzers/RelativeRelocations.hpp"

#include <binaryninja/binaryninjacore.h>
#include <binaryninja/binaryninjaapi.h>

using namespace LIEF::ELF;
using namespace BinaryNinja;

namespace analysis_plugin::elf::analyzers {

bool RelativeRelocations::can_run(BinaryNinja::BinaryView& bv, Binary& elf) {
  for (const DynamicEntry& DT : elf.dynamic_entries()) {
    switch (DT.tag()) {
      case DynamicEntry::TAG::RELR:
      case DynamicEntry::TAG::ANDROID_RELR:
        return true;
      default:
        continue;
    }
  }
  return false;
}

void RelativeRelocations::process_relative(uint64_t addr, uint64_t size) {
  assert(elf_.ptr_size() != 0);
  size_t count = size / elf_.ptr_size();
  define_array_at(translate_addr(addr), type_builder_.ptr_t(), count, "r_relr");
}

void RelativeRelocations::run() {
  if (DynamicEntry* dt_addr = elf_.get(DynamicEntry::TAG::RELR)) {
    if (DynamicEntry* dt_sz = elf_.get(DynamicEntry::TAG::RELRSZ)) {
      process_relative(dt_addr->value(), dt_sz->value());
    }
  }

  if (DynamicEntry* dt_addr = elf_.get(DynamicEntry::TAG::ANDROID_RELR)) {
    if (DynamicEntry* dt_sz = elf_.get(DynamicEntry::TAG::ANDROID_RELRSZ)) {
      process_relative(dt_addr->value(), dt_sz->value());
    }
  }

}

}
