/* Copyright 2022 - 2026 R. Thomas
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
#pragma once
#include "LIEF/DWARF/LexicalBlock.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/Iterator.hpp"
#include "LIEF/rust/range.hpp"
#include "LIEF/rust/optional.hpp"
#include "LIEF/rust/error.hpp"
#include "LIEF/rust/debug_location.hpp"

class DWARF_LexicalBlock : private Mirror<LIEF::dwarf::LexicalBlock> {
  public:
  using Mirror::Mirror;
  using lief_t = LIEF::dwarf::LexicalBlock;

  class it_sub_blocks :
      public ForwardIterator<DWARF_LexicalBlock, LIEF::dwarf::LexicalBlock::Iterator>
  {
    public:
    it_sub_blocks(const DWARF_LexicalBlock::lief_t& src)
      : ForwardIterator(src.sub_blocks()) { }
    auto next() { return ForwardIterator::next(); }
  };

  auto name() const { return get().name(); }

  auto description() const { return get().description(); }

  uint64_t addr(uint32_t& is_set) const {
    return details::make_optional(get().addr(), is_set);
  }

  uint64_t low_pc(uint32_t& is_set) const {
    return details::make_optional(get().low_pc(), is_set);
  }

  uint64_t high_pc(uint32_t& is_set) const {
    return details::make_optional(get().high_pc(), is_set);
  }

  auto size() const {
    return get().size();
  }

  auto ranges() const { return details::make_range(get().ranges()); }

  auto sub_blocks() const {
    return std::make_unique<it_sub_blocks>(get());
  }

};
