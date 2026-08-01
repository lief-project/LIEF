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
#include <cassert>

#include "LIEF/BinaryStream/BinaryStream.hpp"
#include "LIEF/MachO/ChainedPointerAnalysis.hpp"
#include <spdlog/fmt/fmt.h>

namespace LIEF::MachO {
std::ostream& operator<<(
    std::ostream& os,
    const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_rebase_t& chain
) {
  os << fmt::format("target: {:#012x} high8: {:#04x}, next: {:#05x}, "
                    "bind: {}, auth: {}",
                    chain.target, chain.high8, chain.next, (bool)chain.bind,
                    (bool)chain.auth);
  return os;
}

std::ostream& operator<<(
    std::ostream& os,
    const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind_t& chain
) {
  os << fmt::format("ordinal: {:#06x} zero: {:#06x}, addend: {:#07x}, "
                    "next: {:#05x} bind: {}, auth: {}",
                    chain.ordinal, chain.zero, chain.addend, chain.next,
                    (bool)chain.bind, (bool)chain.auth);
  return os;
}

std::ostream& operator<<(
    std::ostream& os,
    const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_rebase_t& chain
) {
  os << fmt::format("target: {:#010x} diversity: {:#06x}, addr_div: {}, "
                    "key: {:#x} next: {:#05x} bind: {}, auth: {}",
                    chain.target, chain.diversity, chain.addr_div, chain.key,
                    chain.next, (bool)chain.bind, (bool)chain.auth);
  return os;
}

std::ostream& operator<<(
    std::ostream& os,
    const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind_t& chain
) {
  os << fmt::format("ordinal: {:#06x} zero: {:#06x}, diversity: {:#06x}, "
                    "addr_div: {} key: {:#x} next: {:#05x} bind: {}, auth: {}",
                    chain.ordinal, chain.zero, chain.diversity, chain.addr_div,
                    chain.key, chain.next, (bool)chain.bind, (bool)chain.auth);
  return os;
}

std::ostream&
    operator<<(std::ostream& os,
               const ChainedPointerAnalysis::dyld_chained_ptr_64_rebase_t& chain) {
  os << fmt::format("target: {:#012x} high8: {:#04x}, reserved: {:#04x}, "
                    "next: {:#06x} bind: {}",
                    chain.target, chain.high8, chain.reserved, chain.next,
                    (bool)chain.bind);
  return os;
}
std::ostream& operator<<(
    std::ostream& os,
    const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_bind24_t& chain
) {

  os << fmt::format("ordinal: {:#08x} zero: {:#04x}, addend: {:#07x}, "
                    "next: {:#05x} bind: {}, auth: {}",
                    chain.ordinal, chain.zero, chain.addend, chain.next,
                    (bool)chain.bind, (bool)chain.auth);
  return os;
}
std::ostream& operator<<(
    std::ostream& os,
    const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_bind24_t& chain
) {
  os << fmt::format("ordinal: {:#08x} zero: {:#04x}, diversity: {:#06x}, "
                    "addr_div: {}, key: {:#x}, next: {:#05x} bind: {}, auth: {}",
                    chain.ordinal, chain.zero, chain.diversity, chain.addr_div,
                    chain.key, chain.next, (bool)chain.bind, (bool)chain.auth);
  return os;
}

std::ostream&
    operator<<(std::ostream& os,
               const ChainedPointerAnalysis::dyld_chained_ptr_64_bind_t& chain) {
  os << fmt::format("ordinal: {:#08x} addend: {:#06x}, reserved: {:#07x}, "
                    "next: {:#06x} bind: {}",
                    chain.ordinal, chain.addend, chain.reserved, chain.next,
                    (bool)chain.bind);
  return os;
}

std::ostream& operator<<(
    std::ostream& os,
    const ChainedPointerAnalysis::dyld_chained_ptr_64_kernel_cache_rebase_t& chain
) {
  os << fmt::format("target: {:#010x} cache_level: {}, diversity: {:#06x}, "
                    "addr_div: {} key: {} next: {:#05x}, auth: {}",
                    chain.target, chain.cache_level, chain.diversity,
                    chain.addr_div, chain.key, chain.next, (bool)chain.is_auth);
  return os;
}

std::ostream&
    operator<<(std::ostream& os,
               const ChainedPointerAnalysis::dyld_chained_ptr_32_rebase_t& chain) {
  os << fmt::format("target: {:#010x} next: {:#04x}, bind: {}", chain.target,
                    chain.next, (bool)chain.bind);
  return os;
}

std::ostream&
    operator<<(std::ostream& os,
               const ChainedPointerAnalysis::dyld_chained_ptr_32_bind_t& chain) {
  os << fmt::format("ordinal: {:#07x} addend: {:#04x}, next: {:#x}, bind: {}",
                    chain.ordinal, chain.addend, chain.next, (bool)chain.bind);
  return os;
}

std::ostream& operator<<(
    std::ostream& os,
    const ChainedPointerAnalysis::dyld_chained_ptr_32_cache_rebase_t& chain
) {
  os << fmt::format("target: {:#08x}, next: {:#x}", chain.target, chain.next);
  return os;
}

std::ostream& operator<<(
    std::ostream& os,
    const ChainedPointerAnalysis::dyld_chained_ptr_32_firmware_rebase_t& chain
) {
  os << fmt::format("target: {:#08x}, next: {:#x}", chain.target, chain.next);
  return os;
}

std::ostream& operator<<(
    std::ostream& os,
    const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_segmented_rebase_t& chain
) {
  os << fmt::format("segment offset: {:#08x}, segment index: {}, next: {:#x}",
                    chain.target_seg_offset, chain.target_seg_index, chain.next);
  return os;
}

std::ostream& operator<<(
    std::ostream& os,
    const ChainedPointerAnalysis::dyld_chained_ptr_arm64e_auth_segmented_rebase_t&
        chain
) {
  os << fmt::format("segment offset: {:#08x}, segment index: {}, next: {:#x}, "
                    "addr_div: {} key: {} diversity: {}, auth: {}",
                    chain.target_seg_offset, chain.target_seg_index, chain.next,
                    chain.addr_div, chain.key, chain.diversity, chain.auth);
  return os;
}

template<class T>
ChainedPointerAnalysis::union_pointer_t create_impl(const T& value) {
  ChainedPointerAnalysis::union_pointer_t out;
  out.content = value;
  std::memcpy(&out.raw, &value,
              sizeof(value) < sizeof(out.raw) ? sizeof(value) : sizeof(out.raw));
  return out;
}


ChainedPointerAnalysis::union_pointer_t
    ChainedPointerAnalysis::get_as(DYLD_CHAINED_PTR_FORMAT fmt) const {
  switch (fmt) {
    case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E:
    case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_KERNEL:
    case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND:
    case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND24:
    {
      if ((bool)dyld_chained_ptr_arm64e_auth_rebase().auth &&
          (bool)dyld_chained_ptr_arm64e_auth_rebase().bind)
      {
        if (fmt == DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND24) {
          return create_impl(dyld_chained_ptr_arm64e_auth_bind24());
        }
        return create_impl(dyld_chained_ptr_arm64e_auth_bind());
      }

      if (dyld_chained_ptr_arm64e_auth_rebase().auth &&
          !dyld_chained_ptr_arm64e_auth_rebase().bind)
      {
        return create_impl(dyld_chained_ptr_arm64e_auth_rebase());
      }
      if (!dyld_chained_ptr_arm64e_auth_rebase().auth &&
          dyld_chained_ptr_arm64e_auth_rebase().bind)
      {
        if (fmt == DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND24) {
          return create_impl(dyld_chained_ptr_arm64e_bind24());
        }
        return create_impl(dyld_chained_ptr_arm64e_bind());
      }

      if (!dyld_chained_ptr_arm64e_auth_rebase().auth &&
          !dyld_chained_ptr_arm64e_auth_rebase().bind)
      {
        return create_impl(dyld_chained_ptr_arm64e_rebase());
      }

      return {};
    }

    case DYLD_CHAINED_PTR_FORMAT::PTR_64:
    case DYLD_CHAINED_PTR_FORMAT::PTR_64_OFFSET:
    {
      if (dyld_chained_ptr_64_rebase().bind) {
        return create_impl(dyld_chained_ptr_64_bind());
      }
      return create_impl(dyld_chained_ptr_64_rebase());
    }

    case DYLD_CHAINED_PTR_FORMAT::PTR_32:
    {
      if (dyld_chained_ptr_32_bind().bind) {
        return create_impl(dyld_chained_ptr_32_bind());
      }
      return create_impl(dyld_chained_ptr_32_rebase());
    }

    case DYLD_CHAINED_PTR_FORMAT::PTR_32_CACHE:
      return create_impl(dyld_chained_ptr_32_cache_rebase());

    case DYLD_CHAINED_PTR_FORMAT::PTR_32_FIRMWARE:
      return create_impl(dyld_chained_ptr_32_firmware_rebase());

    case DYLD_CHAINED_PTR_FORMAT::PTR_64_KERNEL_CACHE:
      return create_impl(dyld_chained_ptr_64_kernel_cache_rebase());

    case DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_SEGMENTED:
    {
      if (dyld_chained_ptr_arm64e_segmented_rebase().auth) {
        return create_impl(dyld_chained_ptr_arm64e_auth_segmented_rebase());
      }
      return create_impl(dyld_chained_ptr_arm64e_segmented_rebase());
    }

    default: return {};
  }
  return {};
}

uint32_t ChainedPointerAnalysis::union_pointer_t::next() const {
  return std::visit(
      [](const auto& ptr) -> uint32_t {
        using T = std::decay_t<decltype(ptr)>;
        if constexpr (std::is_same_v<T, std::monostate>) {
          return 0;
        } else {
          return ptr.next;
        }
      },
      content
  );
}

result<uint32_t> ChainedPointerAnalysis::union_pointer_t::ordinal() const {
  return std::visit(
      [](const auto& ptr) -> result<uint32_t> {
        using T = std::decay_t<decltype(ptr)>;
        if constexpr (std::is_same_v<T, dyld_chained_ptr_arm64e_bind_t> ||
                      std::is_same_v<T, dyld_chained_ptr_arm64e_auth_bind_t> ||
                      std::is_same_v<T, dyld_chained_ptr_arm64e_bind24_t> ||
                      std::is_same_v<T, dyld_chained_ptr_arm64e_auth_bind24_t> ||
                      std::is_same_v<T, dyld_chained_ptr_64_bind_t> ||
                      std::is_same_v<T, dyld_chained_ptr_32_bind_t>)
        {
          return ptr.ordinal;
        } else {
          return make_error_code(lief_errors::not_found);
        }
      },
      content
  );
}

bool ChainedPointerAnalysis::union_pointer_t::is_auth() const {
  return std::visit(
      [](const auto& ptr) -> bool {
        using T = std::decay_t<decltype(ptr)>;
        if constexpr (std::is_same_v<T, dyld_chained_ptr_arm64e_rebase_t> ||
                      std::is_same_v<T, dyld_chained_ptr_arm64e_bind_t> ||
                      std::is_same_v<T, dyld_chained_ptr_arm64e_auth_rebase_t> ||
                      std::is_same_v<T, dyld_chained_ptr_arm64e_auth_bind_t> ||
                      std::is_same_v<T, dyld_chained_ptr_arm64e_bind24_t> ||
                      std::is_same_v<T, dyld_chained_ptr_arm64e_auth_bind24_t> ||
                      std::is_same_v<T,
                                     dyld_chained_ptr_arm64e_segmented_rebase_t> ||
                      std::is_same_v<
                          T, dyld_chained_ptr_arm64e_auth_segmented_rebase_t
                      >)
        {
          return ptr.auth;
        } else {
          return false;
        }
      },
      content
  );
}

result<uint64_t> ChainedPointerAnalysis::union_pointer_t::target() const {
  return std::visit(
      [](const auto& ptr) -> result<uint64_t> {
        using T = std::decay_t<decltype(ptr)>;
        if constexpr (std::is_same_v<T, dyld_chained_ptr_arm64e_rebase_t> ||
                      std::is_same_v<T, dyld_chained_ptr_64_rebase_t>)
        {
          return ptr.unpack_target();
        } else if constexpr (
            std::is_same_v<T, dyld_chained_ptr_arm64e_auth_rebase_t> ||
            std::is_same_v<T, dyld_chained_ptr_64_kernel_cache_rebase_t> ||
            std::is_same_v<T, dyld_chained_ptr_32_rebase_t> ||
            std::is_same_v<T, dyld_chained_ptr_32_cache_rebase_t> ||
            std::is_same_v<T, dyld_chained_ptr_32_firmware_rebase_t>)
        {
          return ptr.target;
        } else if constexpr (
            std::is_same_v<T, dyld_chained_ptr_arm64e_segmented_rebase_t> ||
            std::is_same_v<T, dyld_chained_ptr_arm64e_auth_segmented_rebase_t>)
        {
          return ptr.target_seg_offset;
        } else {
          return make_error_code(lief_errors::not_found);
        }
      },
      content
  );
}

std::ostream& operator<<(std::ostream& os,
                         const ChainedPointerAnalysis::union_pointer_t& ptr) {
  std::visit(
      [&os](const auto& value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (!std::is_same_v<T, std::monostate>) {
          os << value;
        }
      },
      ptr.content
  );
  return os;
}

uint64_t ChainedPointerAnalysis::walk_chain(
    BinaryStream& stream, DYLD_CHAINED_PTR_FORMAT format,
    const std::function<int(uint64_t, const union_pointer_t& ptr)>& callback
) {
  const size_t ptr_sizeof = ChainedPointerAnalysis::ptr_size(format);
  const size_t stride = ChainedPointerAnalysis::stride(format);
  assert(ptr_sizeof == 8 || ptr_sizeof == 4);
  const uint64_t start_pos = stream.pos();
  while (true) {
    uint64_t value = ptr_sizeof == sizeof(uint64_t) ?
                         stream.peek<uint64_t>().value_or(0) :
                         stream.peek<uint32_t>().value_or(0);
    if (value == 0) {
      break;
    }
    ChainedPointerAnalysis analysis(value, ptr_sizeof);
    union_pointer_t ptr = analysis.get_as(format);
    const uint64_t offset = stream.pos();
    if (callback(offset, ptr)) {
      return start_pos - stream.pos();
    }

    const uint32_t next = ptr.next() * stride;
    if (next == 0) {
      break;
    }

    if (!stream.can_read(stream.pos() + next, ptr_sizeof)) {
      break;
    }

    stream.increment_pos(next);
  }
  return stream.pos() - start_pos;
}
}
