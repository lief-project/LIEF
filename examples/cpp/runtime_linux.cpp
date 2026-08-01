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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <format>
#include <ranges>
#include <string>

#include <LIEF/ELF.hpp>
#include <LIEF/logging.hpp>
#include <LIEF/runtime.hpp>
#include <LIEF/runtime/assembler.hpp>

using namespace LIEF::logging;

inline std::string hex(uint64_t value) {
  return std::format("{:#06x}", value);
}

void host_info() {
  info("Host");
  // lief-doc: host-start
  info("    Hostname: {}", LIEF::runtime::Host::name());
  info("    Home:     {}", LIEF::runtime::Host::home_dir());
  info("    Cache:    {}", LIEF::runtime::Host::cache_dir());
  info("    Temp:     {}", LIEF::runtime::Host::tmp_dir());
  info("    Config:   {}", LIEF::runtime::Host::config_dir());
  // lief-doc: host-end

  // lief-doc: host-linux-start
  info("    sys_name:    {}", LIEF::runtime::Linux::Host::sys_name());
  info("    sys_release: {}", LIEF::runtime::Linux::Host::sys_release());
  info("    sys_version: {}", LIEF::runtime::Linux::Host::sys_version());
  info("    hardware:    {}", LIEF::runtime::Linux::Host::hardware());
  // lief-doc: host-linux-end
}

void process_info() {
  info("Process");
  // lief-doc: process-start
  info("    PID:       {}", std::to_string(LIEF::runtime::Process::pid()));
  info("    TID:       {}", std::to_string(LIEF::runtime::Process::tid()));
  info("    Page size: {}", hex(LIEF::runtime::Process::page_size()));
  info("    Arch:      {}",
       std::to_string((uint32_t)LIEF::runtime::Process::arch()));
  info("    Platform:  {}",
       std::to_string((uint32_t)LIEF::runtime::Process::platform()));
  if (auto term = LIEF::runtime::Process::get_env("TERM")) {
    info("    TERM:      {}", *term);
  }
  // lief-doc: process-end

  // lief-doc: process-linux-start
  info("    glibc:     {}", LIEF::runtime::Linux::Process::glibc_version());
  // lief-doc: process-linux-end
}

void modules_info() {
  info("Module API");
  std::unique_ptr<LIEF::runtime::Linux::Module> libc;
  // lief-doc: modules-start
  for (const LIEF::runtime::Module& mod : LIEF::runtime::modules()) {
    info("{}", mod.to_string());
    // Look for the libc
    if (mod.name().ends_with("libc.so")) {
      info("libc.so found: {} ([{}, {}])", mod.path(), hex(mod.imagebase()),
           hex(mod.end()));
      libc.reset(mod.clone().release()->as<LIEF::runtime::Linux::Module>());
    }
  }
  // lief-doc: modules-end

  if (libc == nullptr) {
    return;
  }

  // lief-doc: modules-linux-start
  info("libc path: {}", libc->path());
  if (void* cxa_finalize = libc->dlsym("__cxa_finalize")) {
    info("{}!__cxa_finalize: {}", libc->name(),
         hex(reinterpret_cast<uintptr_t>(cxa_finalize)));
  }

  if (void* malloc_fn = libc->dlsym("malloc")) {
    auto malloc_ptr = reinterpret_cast<uintptr_t>(malloc_fn);
    info("{}!malloc: {}", libc->name(),
         hex(reinterpret_cast<uintptr_t>(malloc_fn)));
    auto malloc_instructions = LIEF::runtime::disassemble(malloc_ptr);

    // Dump the first instructions of malloc
    for (const LIEF::assembly::Instruction& inst :
         malloc_instructions | std::views::take(4))
    {
      info("   {}", inst.to_string());
    }
  }

  // This parses the ELF from its path on the disk
  if (std::unique_ptr<LIEF::ELF::Binary> elf_on_disk = libc->parse_from_path()) {
    if (const LIEF::Symbol* sym = elf_on_disk->get_symbol("__cxa_finalize")) {
      info("__cxa_finalize: {}", hex(sym->value()));
    }
  }

  // This code loads 'librt.so' and wraps the dlopen handle in a Module.
  if (std::unique_ptr<LIEF::runtime::Linux::Module> librt =
          LIEF::runtime::Linux::dlopen("librt.so.1"))
  {
    info("librt loaded: {} (dlopen handle={})", librt->path(),
         hex(reinterpret_cast<uintptr_t>(librt->handle())));

    // Alternately you could do this:
    {
      void* handle = dlopen("librt.so.1", RTLD_NOW);
      auto librt_alt = LIEF::runtime::Linux::Module::from_handle(handle);
    }

    // Parse the ELF directly from memory.
    if (std::unique_ptr<LIEF::ELF::Binary> librt_mem = librt->parse_from_memory())
    {
      // Look for the relocation associated with the **imported** symbol
      // `__cxa_finalize` that is defined in the libc. The relocation holds
      // the address where the function is resolved. Reading this address
      // gives back the same value previously returned by dlsym.
      for (const auto& reloc : librt_mem->relocations()) {
        const auto* sym = reloc.symbol();
        if (sym == nullptr || sym->name() != "__cxa_finalize") {
          continue;
        }
        uintptr_t abs_reloc_addr = librt->imagebase() + reloc.address();
        auto resolved = LIEF::runtime::Memory::read<uint64_t>(abs_reloc_addr);
        info("{} -> {} -> {}", librt->name(), hex(abs_reloc_addr), hex(resolved));
        break;
      }
    }
  }
  // lief-doc: modules-linux-end
}

void memory_example() {
  info("Memory");
  // lief-doc: memory-start
  using Mem = LIEF::runtime::Memory;
  auto chunk = Mem::mmap(LIEF::runtime::Process::page_size(),
                         Mem::MP_ANONYMOUS | Mem::MP_PRIVATE,
                         Mem::P_READ | Mem::P_WRITE | Mem::P_EXEC);

  if (!chunk) {
    return;
  }

  std::vector<uint8_t> raw_inst = LIEF::runtime::assemble(chunk->addr(), R"asm(
    .global _start

    .text
    _start:
        push 1
        pop  rax
        mov  edi, eax
        lea  rsi, [rip + msg]
        mov  rdx, 28
        syscall
        ret

    msg:
        .ascii "LIEF Runtime Extended Demo\n"
  )asm");

  // Change the permission to R-X and invoke the JITed function
  chunk->make_rx();

  using shellcode_t = void (*)();
  auto hello_jit = reinterpret_cast<shellcode_t>(chunk->addr());
  hello_jit();

  const char new_msg[] = "Hello C++ runtime World!\n\0";
  std::string_view view_inst(reinterpret_cast<const char*>(raw_inst.data()),
                             raw_inst.size());
  size_t pos = view_inst.find("LIEF Runtime Extended");
  assert(pos != std::string_view::npos);
  chunk->make_rw();
  Mem::write(reinterpret_cast<const uint8_t*>(new_msg), sizeof(new_msg) - 1,
             chunk->addr() + pos);
  chunk->make_rx();

  hello_jit();

  // Don't miss good practices!
  (void)chunk->deallocate();
  // lief-doc: memory-end
}

int main(int /*argc*/, char** /*argv*/) {
  LIEF::logging::Scoped scope(Level::Info);
  if (!LIEF::runtime::is_enabled()) {
    err("LIEF's runtime is not enabled");
    return EXIT_SUCCESS;
  }

  host_info();
  process_info();
  modules_info();
  memory_example();
  return EXIT_SUCCESS;
}
