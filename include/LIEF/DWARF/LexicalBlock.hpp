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
#ifndef LIEF_DWARF_LEXICAL_BLOCK_H
#define LIEF_DWARF_LEXICAL_BLOCK_H

#include "LIEF/visibility.h"
#include "LIEF/iterators.hpp"
#include "LIEF/optional.hpp"
#include "LIEF/range.hpp"

#include <memory>
#include <string>
#include <cstdint>

namespace LIEF {
namespace dwarf {

namespace details {
class LexicalBlock;
class LexicalBlockIt;
}

/// This class represents a DWARF lexical block (`DW_TAG_lexical_block`)
class LIEF_API LexicalBlock {
  public:
  class LIEF_API Iterator {
    public:
    using iterator_category = std::bidirectional_iterator_tag;
    using value_type = std::unique_ptr<LexicalBlock>;
    using difference_type = std::ptrdiff_t;
    using pointer = LexicalBlock*;
    using reference = std::unique_ptr<LexicalBlock>&;
    using implementation = details::LexicalBlockIt;

    class LIEF_API PointerProxy {
      // Inspired from LLVM's iterator_facade_base
      friend class Iterator;
      public:
      pointer operator->() const { return R.get(); }

      private:
      value_type R;

      template <typename RefT>
      PointerProxy(RefT &&R) : R(std::forward<RefT>(R)) {} // NOLINT(bugprone-forwarding-reference-overload)
    };

    Iterator(const Iterator&);
    Iterator(Iterator&&) noexcept;
    Iterator(std::unique_ptr<details::LexicalBlockIt> impl);
    ~Iterator();

    friend LIEF_API bool operator==(const Iterator& LHS, const Iterator& RHS);
    friend LIEF_API bool operator!=(const Iterator& LHS, const Iterator& RHS) {
      return !(LHS == RHS);
    }

    Iterator& operator++();
    Iterator& operator--();

    Iterator operator--(int) {
      Iterator tmp = *static_cast<Iterator*>(this);
      --*static_cast<Iterator *>(this);
      return tmp;
    }

    Iterator operator++(int) {
      Iterator tmp = *static_cast<Iterator*>(this);
      ++*static_cast<Iterator *>(this);
      return tmp;
    }

    std::unique_ptr<LexicalBlock> operator*() const;

    PointerProxy operator->() const {
      return static_cast<const Iterator*>(this)->operator*();
    }

    private:
    std::unique_ptr<details::LexicalBlockIt> impl_;
  };

  using sub_blocks_it = iterator_range<Iterator>;

  LexicalBlock(std::unique_ptr<details::LexicalBlock> impl);
  LexicalBlock() = delete;
  LexicalBlock& operator=(const LexicalBlock&) = delete;
  LexicalBlock(const LexicalBlock&) = delete;

  /// Return the *name* associated with this lexical block or an
  /// empty string
  std::string name() const;

  /// Return the description associated with this lexical block or an
  /// empty string
  std::string description() const;

  /// Return an iterator over the sub-LexicalBlock owned by this block.
  sub_blocks_it sub_blocks() const;

  /// Return the start address of this block
  optional<uint64_t> addr() const;

  /// Return the size of this block as the difference of the highest address and
  /// the lowest address.
  uint64_t size() const;

  /// Return the lowest virtual address owned by this block.
  optional<uint64_t> low_pc() const;

  /// Return the highest virtual address owned by this block.
  optional<uint64_t> high_pc() const;

  /// Return a list of address ranges owned by this block.
  ///
  /// If the lexical block owns a contiguous range, it should return
  /// **a single** range.
  std::vector<range_t> ranges() const;

  ~LexicalBlock();

  LIEF_LOCAL static
    std::unique_ptr<LexicalBlock> create(std::unique_ptr<details::LexicalBlock> impl);

  protected:
  std::unique_ptr<details::LexicalBlock> impl_;
};

}
}
#endif
