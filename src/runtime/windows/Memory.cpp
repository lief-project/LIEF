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
#include "LIEF/runtime/Memory.hpp"
#include "LIEF/runtime/Process.hpp"
#include "LIEF/runtime/utils.hpp"
#include "logging.hpp"

#include <windows.h>

namespace LIEF::runtime {

inline int get_win_flags(uint32_t flags) {
  switch (flags) {
    default: logging::fatal_error("Invalid permission");
    case Memory::P_NONE: return PAGE_NOACCESS;
    case Memory::P_READ: return PAGE_READONLY;
    case Memory::P_WRITE: return PAGE_READWRITE;
    case Memory::P_EXEC: return PAGE_EXECUTE;

    case Memory::P_READ | Memory::P_WRITE: return PAGE_READWRITE;

    case Memory::P_READ | Memory::P_EXEC: return PAGE_EXECUTE_READ;

    case Memory::P_WRITE | Memory::P_EXEC: return PAGE_EXECUTE_READWRITE;

    case Memory::P_READ | Memory::P_WRITE | Memory::P_EXEC:
      return PAGE_EXECUTE_READWRITE;
  }

  logging::fatal_error("Unreachable");
}


inline uint32_t allocation_granularity() {
  static const uint32_t GRANULARITY = [] {
    SYSTEM_INFO info = {};
    GetNativeSystemInfo(&info);
    return (uint32_t)info.dwAllocationGranularity;
  }();
  return GRANULARITY;
}

std::string Memory::perm_str(uint32_t flags) {
  std::string flags_str = "---";
  if (flags & P_READ) {
    flags_str[0] = 'r';
  }

  if (flags & P_WRITE) {
    flags_str[1] = 'w';
  }

  if (flags & P_EXEC) {
    flags_str[2] = 'x';
  }
  return flags_str;
}

std::string Memory::Chunk::to_string() const {
  if (!is_valid()) {
    return "<empty chunk>";
  }

  if (size() == 0) {
    return fmt::format("[{:#018x}, ...]", addr());
  }

  return fmt::format("[{:#018x}, {:#018x}]", addr(), addr() + size());
}


Memory::Chunk& Memory::Chunk::cache_flush() {
  FlushInstructionCache(GetCurrentProcess(), addr_ptr(), size());
  return *this;
}

std::optional<Memory::Chunk> Memory::mmap(size_t size, uint32_t flags,
                                          uint32_t perms) {
  return Memory::mmap_hint(/*hint=*/0, size, flags, perms);
}

std::optional<Memory::Chunk> Memory::mmap_hint(uint64_t hint, size_t size,
                                               uint32_t flags, uint32_t perms) {
  if (size == 0) {
    return std::nullopt;
  }

  const uintptr_t addr =
      hint == 0 ? 0 : runtime::page_align(hint, allocation_granularity());

  if (hint != 0 && addr == 0) {
    LIEF_ERR("VirtualAlloc: invalid hint: {:#016x}", hint);
    return std::nullopt;
  }

  DWORD win_perms = get_win_flags(perms);
  void* ret = ::VirtualAlloc(/*lpAddress=*/reinterpret_cast<void*>(addr),
                             /*dwSize=*/size,
                             /*flAllocationType=*/MEM_RESERVE | MEM_COMMIT,
                             /*flProtect=*/win_perms);
  if (ret == nullptr) {
    // The hint might be the reason of this failure so let's try again without
    // it, unless the caller explicitly asked for a fixed mapping.
    if (addr != 0 && (flags & MP_FIXED) == 0) {
      LIEF_DEBUG("VirtualAlloc failed for the hint {:#016x} ({}). "
                 "Trying without it",
                 addr, GetLastError());
      return Memory::mmap_hint(/*hint=*/0, size, flags, perms);
    }
    LIEF_ERR("VirtualAlloc failed with error code: {}", GetLastError());
    return std::nullopt;
  }

  return Chunk(ret, size, perms);
}

uintptr_t Memory::Chunk::page_start() const {
  if (!is_valid()) {
    return 0;
  }
  return runtime::page_start(addr(), Process::page_size());
}

uintptr_t Memory::Chunk::page_end() const {
  if (!is_valid()) {
    return 0;
  }
  return runtime::page_end(addr() + size(), Process::page_size());
}

ok_error_t Memory::munmap(Chunk& C) {
  if (!C.is_valid()) {
    LIEF_DEBUG("Error: {}:{} - Invalid chunk", __FUNCTION__, __LINE__);
    return make_error_code(lief_errors::runtime_error);
  }

  if (C.size() == 0) {
    LIEF_DEBUG("Error: {}:{} - Missing chunk size", __FUNCTION__, __LINE__);
    return make_error_code(lief_errors::runtime_error);
  }

  int ret = VirtualFree(C.addr_ptr(), 0, MEM_RELEASE);
  if (ret == 0) {
    LIEF_ERR("munmap {} failed: {}", C.to_string(), GetLastError());
    return make_error_code(lief_errors::runtime_error);
  }
  return ok();
}

ok_error_t Memory::mprotect(Memory::Chunk& C, uint32_t flags) {
  if (!C.is_valid()) {
    LIEF_DEBUG("Error: {}:{} - Invalid chunk", __FUNCTION__, __LINE__);
    return make_error_code(lief_errors::runtime_error);
  }

  if (C.size() == 0) {
    LIEF_DEBUG("Error: {}:{} - Missing chunk size", __FUNCTION__, __LINE__);
    return make_error_code(lief_errors::runtime_error);
  }

  const uintptr_t pstart = C.page_start();
  const uintptr_t pend = C.page_end();
  const uintptr_t len = pend - pstart;

  DWORD win_perms = get_win_flags(flags);
  DWORD old_perms = 0;
  int ret = VirtualProtect((void*)pstart, len, win_perms, &old_perms);
  if (ret == 0) {
    LIEF_ERR("mprotect [{:#018x}, {:#018x}] -> {} ({}) failed: {}", pstart, pend,
             perm_str(flags), win_perms, GetLastError());
    return make_error_code(lief_errors::runtime_error);
  }

  return ok();
}

}
