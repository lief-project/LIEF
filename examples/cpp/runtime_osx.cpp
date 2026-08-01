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
#include <format>
#include <optional>
#include <ranges>
#include <string>

#include <LIEF/MachO.hpp>
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

  // lief-doc: host-osx-start
  info("    Version:  {}", LIEF::runtime::osx::Host::os_version_name());
  info("    SIP:      {}",
       LIEF::runtime::osx::Host::is_sip_enabled() ? "enabled" : "disabled");
  // lief-doc: host-osx-end
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
  // lief-doc: process-end

  // lief-doc: process-osx-start
  info("    dyld:      {}", LIEF::runtime::osx::Process::dyld_version());
  // lief-doc: process-osx-end
}

void modules_info() {
  info("Module API");

  // Module referencing libsystem_c.dylib in memory
  std::unique_ptr<LIEF::runtime::osx::Module> libsystem;

  // lief-doc: modules-start
  auto mods = LIEF::runtime::modules();
  for (auto it = mods.begin(); it != mods.end(); ++it) {
    info("{}", it->to_string());
    // Look for the C library
    if (it->name().ends_with("libsystem_c.dylib")) {
      info("libsystem_c.dylib found: {} ([{}, {}])", it->path(),
           hex(it->imagebase()), hex(it->end()));
      // Transfer ownership so 'libsystem' outlives this loop
      std::unique_ptr<LIEF::runtime::Module> mod = it.yield();
      libsystem.reset(mod.release()->as<LIEF::runtime::osx::Module>());
    }
  }
  // lief-doc: modules-end

  if (libsystem == nullptr) {
    return;
  }

  // lief-doc: modules-osx-start
  info("libsystem_c path: {}", libsystem->path());
  if (void* p_arc4_init = libsystem->dlsym("arc4_init")) {
    info("{}!arc4_init: {}", libsystem->name(),
         hex(reinterpret_cast<uintptr_t>(p_arc4_init)));

    // Disassemble malloc directly from its resolved memory address
    auto instructions =
        LIEF::runtime::disassemble(reinterpret_cast<uintptr_t>(p_arc4_init));
    for (const LIEF::assembly::Instruction& inst :
         instructions | std::views::take(4))
    {
      info("    {}", inst.to_string());
    }
  }

  // libsystem->path() looks like a valid path but libsystem_c.dylib lives
  // in the dyld-shared-cache. Therefore, it's pointless to try to parse the
  // library from its filepath as the library does not exist on the disk
  std::unique_ptr<LIEF::MachO::Binary> macho_on_disk;
  {
    LIEF::logging::Scoped disable_logger(LIEF::logging::LEVEL::OFF);
    macho_on_disk = libsystem->parse_from_path();
  }
  if (macho_on_disk == nullptr) {
    info("As expected, {} is not present in the filesystem", libsystem->path());
  }

  // But we can parse it from memory:
  if (std::unique_ptr<LIEF::MachO::Binary> macho_memory =
          libsystem->parse_from_memory())
  {
    info("in-memory imagebase: {}", hex(macho_memory->imagebase()));
    for (const LIEF::MachO::Symbol& S : macho_memory->exported_symbols()) {
      info(std::format("{:10}: {:#010x}", S.name(), S.value()));
    }
  }
  // lief-doc: modules-osx-end
}

void memory_example() {
  info("Memory");
  // lief-doc: memory-start
  // The JIT below allocates and executes RWX memory. On macOS this is only
  // permitted when SIP is disabled.
  if (LIEF::runtime::osx::Host::is_sip_enabled()) {
    warn("SIP is enabled: skipping the JIT memory example");
    return;
  }

  using Mem = LIEF::runtime::Memory;
  // Note the `MP_JIT` here that is used to switch the allocated chunk into R-X
  // once the shellcode is committed.
  auto chunk = Mem::mmap(LIEF::runtime::Process::page_size(),
                         Mem::MP_ANONYMOUS | Mem::MP_PRIVATE | Mem::MP_JIT,
                         Mem::P_READ | Mem::P_WRITE);

  if (!chunk) {
    return;
  }

  class Config : public LIEF::assembly::AssemblerConfig {
    public:
    std::optional<uint64_t> resolve_symbol(const std::string& name) override {
      // The message to print
      static constexpr char HELLO[] = "Hello World\n";
      static constexpr uint32_t HELLO_LEN = sizeof(HELLO) - 1;

      // libSystem re-exports the libc symbols (write, ...)
      static auto libsystem = LIEF::runtime::osx::dlopen("libSystem.B.dylib");

      if (libsystem == nullptr) {
        err("Failed to dlopen libSystem.B.dylib");
        return std::nullopt;
      }

      // Resolve the symbols that are used by the shellcode
      if (name == "write") {
        return reinterpret_cast<uint64_t>(libsystem->dlsym("write"));
      }

      if (name == "var_msg") {
        return reinterpret_cast<uint64_t>(HELLO);
      }

      if (name == "var_msg_len") {
        return HELLO_LEN;
      }

      return std::nullopt;
    }
  };

  Config config;

  // clang-format off

  // Shellcode dynamically compiled and whose referenced symbols are resolved
  // at runtime by the provided Config
  std::vector<uint8_t> raw_inst = LIEF::runtime::assemble(chunk->addr(), R"asm(
    .text
        .global main
        .align 2

    main:
        stp     x29, x30, [sp, -16]!
        mov     x29, sp

        // Here we use symbols that are **dynamically** resolved by the
        // AssemblerConfig
        ldr     x8, =write          // write(2) libc wrapper
        ldr     x1, =var_msg        // buffer
        ldr     w2, =var_msg_len    // length

        // write(STDOUT_FILENO, msg, len)
        mov     x0, 1
        blr     x8

        mov     x0, xzr
        ldp     x29, x30, [sp], 16
        ret
  )asm", config);
  // clang-format on

  // Flush the instruction cache
  chunk->cache_flush();

  // Change the permission to R-X and invoke the JITed function.
  chunk->make_rx();

  using shellcode_t = void (*)();
  auto hello_jit = reinterpret_cast<shellcode_t>(chunk->addr());

  // This call prints the message "Hello World" on the console
  hello_jit();

  // Don't miss good practices!
  (void)chunk->deallocate();
  // lief-doc: memory-end
}

int main(int /*argc*/, char** /*argv*/) {
  LIEF::logging::Scoped scope(LEVEL::INFO);
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
