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
#include <string_view>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <format>
#include <optional>
#include <ranges>
#include <string>

#include <LIEF/ELF.hpp>
#include <LIEF/logging.hpp>
#include <LIEF/runtime.hpp>
#include <LIEF/runtime/android.hpp>
#include <LIEF/runtime/assembler.hpp>
#include <LIEF/runtime/config.h>

#if defined(LIEF_RUNTIME_PLATFORM_ANDROID)
  #include <android/log.h>
#endif

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

  // lief-doc: host-android-start
  if (auto sdk = LIEF::runtime::android::Host::sdk_version()) {
    info("    SDK:      {}", std::to_string(*sdk));
  }
  // lief-doc: host-android-end
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

  // lief-doc: process-android-start
  if (auto prop = LIEF::runtime::android::Process::get_system_property(
          "ro.build.version.sdk"
      ))
  {
    info("    {}: {} (serial: {})", prop->name(), prop->value(),
         std::to_string(prop->serial()));
  }

  for (const auto& prop : LIEF::runtime::android::Process::properties()) {
    info("    {}: {} (serial: {})", prop.name(), prop.value(),
         std::to_string(prop.serial()));
  }
  // lief-doc: process-android-end
}

void modules_info() {
  info("Module API");
  std::unique_ptr<LIEF::runtime::android::Module> libc;
  // lief-doc: modules-start
  for (const LIEF::runtime::Module& mod : LIEF::runtime::modules()) {
    info("{}", mod.to_string());
    // Look for the Bionic C library
    if (mod.name().ends_with("libc.so")) {
      info("libc.so found: {} ([{}, {}])", mod.path(), hex(mod.imagebase()),
           hex(mod.end()));
      libc.reset(mod.clone().release()->as<LIEF::runtime::android::Module>());
    }
  }
  // lief-doc: modules-end

  if (libc == nullptr) {
    return;
  }

  // lief-doc: modules-android-start
  info("libc path: {}", libc->path());
  if (void* cxa_finalize = libc->dlsym("__cxa_finalize")) {
    info("{}!__cxa_finalize: {}", libc->name(),
         hex(reinterpret_cast<uintptr_t>(cxa_finalize)));
  }

  if (void* malloc_fn = libc->dlsym("malloc")) {
    auto malloc_ptr = reinterpret_cast<uintptr_t>(malloc_fn);
    info("{}!malloc: {}", libc->name(), hex(malloc_ptr));

    auto malloc_instructions = LIEF::runtime::disassemble(malloc_ptr);

    // Dump the first instructions of malloc
    for (const LIEF::assembly::Instruction& inst :
         malloc_instructions | std::views::take(4))
    {
      info("   {}", inst.to_string());
    }
  }

  if (std::unique_ptr<LIEF::ELF::Binary> elf_on_disk = libc->parse_from_path()) {
    if (const LIEF::Symbol* sym = elf_on_disk->get_symbol("__cxa_finalize")) {
      info("__cxa_finalize: {}", hex(sym->value()));
    }
  }

  if (std::unique_ptr<LIEF::runtime::android::Module> liblog =
          LIEF::runtime::android::dlopen("liblog.so"))
  {
    info("liblog loaded: {} (dlopen handle={})", liblog->path(),
         hex(reinterpret_cast<uintptr_t>(liblog->handle())));

    if (void* log_print = liblog->dlsym("__android_log_print")) {
      info("{}!__android_log_print: {}", liblog->name(),
           hex(reinterpret_cast<uintptr_t>(log_print)));
    }
  }
  // lief-doc: modules-android-end
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

  struct Config : LIEF::assembly::AssemblerConfig {
    std::optional<uint64_t> resolve_symbol(const std::string& name) override {
      std::unique_ptr<LIEF::runtime::android::Module> libc =
          LIEF::runtime::android::dlopen("libc.so");
      if (libc == nullptr) {
        err("Failed to dlopen libc.so");
        return std::nullopt;
      }

      if (name == "write") {
        return reinterpret_cast<uintptr_t>(libc->dlsym("write"));
      }
      return std::nullopt;
    }
  } config;

  std::vector<uint8_t> raw_inst = LIEF::runtime::assemble(chunk->addr(), R"asm(
  .text
      .global main
      .align 2

  main:
      stp     x29, x30, [sp, -16]!
      mov     x29, sp

      ldr     x8, =write

      mov     x0, 1    // STDOUT_FILENO
      adr     x1, msg  // buf = &msg
      mov     x2, 27   // len("LIEF Runtime Extended Demo\n")
      blr     x8       // write(STDOUT_FILENO, msg, 27)

      ldp     x29, x30, [sp], 16
      ret

  msg:
      .ascii "LIEF Runtime Extended Demo\n"
  )asm",
                                                          config);

  // Disassemble the JITed stub from memory
  auto instructions = LIEF::runtime::disassemble(chunk->addr());
  for (const LIEF::assembly::Instruction& inst :
       instructions | std::views::take(9))
  {
    info("{}", inst.to_string());
  }

  // Dump as raw bytes
  std::vector<uint8_t> raw_bytes;
  Mem::read(chunk->addr(), raw_bytes, raw_inst.size());
  std::string hex_bytes;
  for (uint8_t byte : raw_bytes) {
    if (!hex_bytes.empty()) {
      hex_bytes += ':';
    }
    hex_bytes += std::format("{:02x}", static_cast<unsigned>(byte));
  }
  info("{}", hex_bytes);

  // Flush the instruction cache before executing the freshly written code.
  // This is required on AArch64.
  chunk->cache_flush();

  // Change the permission to R-X and invoke the JITed function
  chunk->make_rx();

  using shellcode_t = void (*)();
  auto hello_jit = reinterpret_cast<shellcode_t>(chunk->addr());
  hello_jit();

  // Change the message
  const char new_msg[] = "Hello C++ runtime World!\n";
  std::string_view view_inst(reinterpret_cast<const char*>(raw_inst.data()),
                             raw_inst.size());
  size_t pos = view_inst.find("LIEF Runtime");
  assert(pos != std::string_view::npos);
  chunk->make_rw();
  Mem::write(reinterpret_cast<const uint8_t*>(new_msg), sizeof(new_msg) - 1,
             chunk->addr() + pos);
  chunk->make_rx();
  chunk->cache_flush();

  hello_jit();

  // Don't miss good practices!
  (void)chunk->deallocate();
  // lief-doc: memory-end
}

int main(int /*argc*/, char** /*argv*/) {
#if defined(LIEF_RUNTIME_PLATFORM_ANDROID)
  __android_log_set_logger(__android_log_stderr_logger);
#endif
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
