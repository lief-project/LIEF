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
#ifndef LIEF_RUNTIME_MEMORY_LAYOUT_H
#define LIEF_RUNTIME_MEMORY_LAYOUT_H

#include <string_view>
#include <cstdint>
#include <memory>
#include <ostream>
#include <string>
#include <utility>

#include "LIEF/compiler_attributes.hpp"
#include "LIEF/iterators.hpp"
#include "LIEF/visibility.h"

namespace LIEF::runtime {

namespace details {
class MemoryLayoutIt;
}

/// This class exposes the memory layout of the current process
class LIEF_API MemoryLayout {
  public:
  /// A contiguous range of memory mapped in the current process
  class Region {
    public:
    Region() = default;
    Region(std::string name, uint64_t addr, uint64_t size) :
      name_(std::move(name)),
      addr_(addr),
      size_(size) {}

    Region(const Region&) = default;
    Region& operator=(const Region&) = default;

    Region(Region&&) noexcept = default;
    Region& operator=(Region&&) noexcept = default;

    ~Region() = default;

    /// Name associated with the region: name/path of the module
    /// mapped at this address (e.g. `libc.so.6`) or the identifier of a
    /// region that is not backed by a file (e.g. `[stack]`, `[heap]`).
    ///
    /// It can be empty for anonymous regions.
    std::string_view name() const LIEF_LIFETIMEBOUND {
      return name_;
    }

    /// Address at which the region starts
    uint64_t addr() const {
      return addr_;
    }

    /// Size of the region
    uint64_t size() const {
      return size_;
    }

    /// Address at which the region ends
    uint64_t end_addr() const {
      return addr() + size();
    }

    /// Whether the given address is within this region
    bool contains(uint64_t addr) const {
      return addr_ <= addr && addr < end_addr();
    }

    std::string to_string() const;

    LIEF_API friend std::ostream& operator<<(std::ostream& os,
                                             const Region& region) {
      os << region.to_string();
      return os;
    }

    private:
    std::string name_;
    uint64_t addr_ = 0;
    uint64_t size_ = 0;
  };

  /// Forward iterator over the regions of the memory layout
  class Iterator final
    : public iterator_facade_base<Iterator, std::forward_iterator_tag, Region,
                                  std::ptrdiff_t, const Region*, const Region&> {
    public:
    using implementation = details::MemoryLayoutIt;
    using iterator_facade_base::operator++;

    LIEF_API Iterator();

    LIEF_API Iterator(const Iterator&);
    LIEF_API Iterator& operator=(const Iterator&);

    LIEF_API Iterator(Iterator&&) noexcept;
    LIEF_API Iterator& operator=(Iterator&&) noexcept;

    LIEF_API Iterator(std::unique_ptr<details::MemoryLayoutIt> impl);
    LIEF_API ~Iterator();

    friend LIEF_API bool operator==(const Iterator& LHS, const Iterator& RHS);
    friend LIEF_API bool operator!=(const Iterator& LHS, const Iterator& RHS) {
      return !(LHS == RHS);
    }

    // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
    LIEF_API Iterator& operator++();

    LIEF_API const Region& operator*() const LIEF_LIFETIMEBOUND;

    // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
    LIEF_API const Region* operator->() const LIEF_LIFETIMEBOUND;

    /// Transfer ownership of the region at the current position to the
    /// caller. Returns `nullptr` if the iterator is past-the-end.
    LIEF_API std::unique_ptr<Region> yield();

    private:
    void load() const;

    std::unique_ptr<details::MemoryLayoutIt> impl_;
    mutable std::unique_ptr<Region> cached_;
  };
};

using memory_layout_it = iterator_range<MemoryLayout::Iterator>;

/// Return an iterator over the memory layout of the current process
LIEF_API memory_layout_it memory_layout();

}
#endif
