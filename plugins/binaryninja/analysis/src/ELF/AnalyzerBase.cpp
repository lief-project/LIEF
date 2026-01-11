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
#include <cctype>

#include "log.hpp"
#include "binaryninja/analysis/ELF/AnalyzerBase.hpp"
#include "LIEF/ELF.hpp"
#include "LIEF/BinaryStream/SpanStream.hpp"

#include <binaryninja/binaryninjacore.h>
#include <binaryninja/binaryninjaapi.h>

using namespace LIEF::ELF;

namespace bn = BinaryNinja;

namespace analysis_plugin::elf {

std::string is_string(LIEF::SpanStream& stream, size_t minsz = 4) {
  std::string current;
  while (stream) {
    auto c = stream.read<uint8_t>();
    if (!c) {
      break;
    }

    // Terminator
    if (*c == '\0') {
      if (current.size() >= minsz) {
        return current;
      }
      return "";
    }

    // Valid char
    if (std::isprint(*c) == 0) {
      return "";
    }

    current.push_back((char)*c);
  }
  return "";
}

AnalyzerBase::AnalyzerBase(BinaryNinja::BinaryView& bv, Binary& elf,
             TypeBuilder& type_builder) :
  analysis_plugin::AnalyzerBase(bv), elf_(elf), type_builder_(type_builder),
  default_image_base_(elf_.imagebase()), default_virtual_size(elf_.virtual_size())
{}

uint64_t AnalyzerBase::translate_addr(uint64_t addr, bool revert) const {
  if (!revert) {
    if (addr >= elf_.imagebase()) {
      return (addr - elf_.imagebase()) + bv_.GetImageBase();
    }
    return addr;
  }

  if (addr >= bv_.GetImageBase()) {
    return (addr - bv_.GetImageBase()) + elf_.imagebase();
  }
  return addr;
}

bool AnalyzerBase::apply_relocation(const Relocation& R) {
  // As of Binary Ninja version 5.2.8133 (2025-08-DD), the
  // `BinaryView::DefineRelocation` method does not effectively apply a new
  // relocation to an existing binary view.
  //
  // To work around this limitation, we manually write the resolved relocation
  // value at the specified address.
  //
  // However, this approach has a drawback: any subsequent (re)rebase operations
  // may not be consistent with the changes made.
  assert(R.size() != -1);
  auto resolved = R.resolve(bv_.GetImageBase());
  if (!resolved) {
    return false;
  }

  const size_t reloc_bytes_size = R.size() / 8;
  uint64_t taddr = translate_addr(R.address());
  uint64_t content = 0; // for implicit addend
  bv_.Read(&content, taddr, reloc_bytes_size);
  uint64_t value = *resolved + content;

  // Ensure that the resolved address is in the memory range of the program.
  // This check also prevent from running twice relocation on the same address.
  if ((R.is_rela() || R.is_android_packed()) && content > 0) {
    BN_INFO("Relocation 0x{:010x} already processed", taddr);
    return true;
  }

  bv_.Write(taddr, &value, reloc_bytes_size);
  define_relocated_type(R, value);
  return true;
}

void AnalyzerBase::define_relocated_type(const Relocation& R, uint64_t ttarget) {
  uint64_t taddr = translate_addr(R.address());

  // The relocation is resolved with the BinaryView's imagebase (see: apply_relocation)
  // Therefore, to get the original target, we need to revert it
  uint64_t target = translate_addr(ttarget, /*revert=*/true);

  const auto default_define = [&] () {
    define_type_at(taddr, type_builder_.void_ptr_t(),
      /*force=*/[] (BinaryNinja::DataVariable& var) {
        return !var.type->IsPointer();
    });
  };

  const Segment* seg = elf_.segment_from_virtual_address(target);
  if (seg == nullptr) {
    return default_define();
  }

  if (seg->type() == Segment::TYPE::LOAD && seg->flags() == Segment::FLAGS::R) {
    std::unique_ptr<LIEF::SpanStream> stream = seg->stream();
    if (stream == nullptr) {
      return default_define();
    }
    stream->setpos(target - seg->virtual_address());
    if (std::string str = is_string(*stream); !str.empty()) {
      define_array_at(ttarget, type_builder_.char_(), str.size() + 1,
        /*name=*/std::nullopt, /*force=*/false);
      define_type_at(taddr, type_builder_.c_str(),
        /*force=*/[] (BinaryNinja::DataVariable& var) {
          return !var.type->IsPointer();
      });
      return;
    }

    return default_define();
  }

  if (seg->type() == Segment::TYPE::LOAD &&
      seg->flags() == (Segment::FLAGS::R | Segment::FLAGS::X))
  {
    // Likely a function. Check if it is defined
    if (bn::Ref<bn::Symbol> sym = bv_.GetSymbolByAddress(ttarget)) {
      if (sym->GetType() == BNSymbolType::FunctionSymbol) {
        define_type_at(taddr, type_builder_.generic_func_ptr_t(),
          /*force=*/[] (BinaryNinja::DataVariable& var) {
            return !var.type->IsPointer();
        });
        return;
      }
      return default_define();
    }

    bv_.CreateUserFunction(bv_.GetDefaultPlatform(), ttarget);
    define_type_at(taddr, type_builder_.generic_func_ptr_t(),
      /*force=*/[] (BinaryNinja::DataVariable& var) {
        return !var.type->IsPointer();
    });
    return;
  }

  return default_define();
}
}
