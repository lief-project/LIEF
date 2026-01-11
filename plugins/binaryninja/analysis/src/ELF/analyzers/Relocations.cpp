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
#include "binaryninja/analysis/ELF/analyzers/Relocations.hpp"

#include <binaryninja/binaryninjacore.h>
#include <binaryninja/binaryninjaapi.h>

using namespace LIEF::ELF;
using namespace BinaryNinja;

namespace analysis_plugin::elf::analyzers {

bool Relocations::can_run(BinaryNinja::BinaryView& bv, Binary& elf) {
  return !elf.relocations().empty();
}

void Relocations::run() {
  for (const LIEF::ELF::Relocation& R : elf_.relocations()) {
    std::vector<Ref<BinaryNinja::Relocation>> relocations =
      bv_.GetRelocationsAt(translate_addr(R.address()));

    if (!relocations.empty()) {
      continue;
    }

    if (R.size() == -1) {
      BN_WARN("Can't apply relocation '{}': Unknown size", to_string(R.type()));
      continue;
    }

    if (R.size() > sizeof(uint64_t) * 8) {
      BN_WARN("Can't apply relocation '{}': wrong size", to_string(R.type()));
      continue;
    }

    if (!apply_relocation(R)) {
      BN_WARN("LIEF couldn't apply relocation: 0x{:010x} - {}", R.address(),
               to_string(R.type()));
    }
  }
}

}
