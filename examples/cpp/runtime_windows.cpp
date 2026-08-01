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

#include <LIEF/PE.hpp>
#include <LIEF/logging.hpp>
#include <LIEF/runtime.hpp>

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

  // lief-doc: host-windows-start
  info("    Version:  {}", LIEF::runtime::windows::Host::version().to_string());
  // lief-doc: host-windows-end
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
  if (auto userdomain = LIEF::runtime::Process::get_env("USERDOMAIN")) {
    info("    USERDOMAIN:{}", *userdomain);
  }
  // lief-doc: process-end

  // lief-doc: process-windows-start
  if (auto peb = LIEF::runtime::windows::Process::peb()) {
    info("    PEB.BeingDebugged:          {}",
         peb->being_debugged() ? "true" : "false");
    info("    PEB.Ldr:                    {}", hex(peb->ldr()));
    info("    PEB.ProcessParameters:      {}", hex(peb->process_parameters()));
    info("    PEB.AtlThunkSListPtr:       {}", hex(peb->atl_thunk_slist_ptr()));
    info("    PEB.AtlThunkSListPtr32:     {}", hex(peb->atl_thunk_slist_ptr32()));
    info("    PEB.PostProcessInitRoutine: {}",
         hex(peb->post_process_init_routine()));
    info("    PEB.SessionId:              {}", hex(peb->session_id()));
  }
  // lief-doc: process-windows-end

  // lief-doc: peb-modules-start
  if (auto peb = LIEF::runtime::windows::Process::peb()) {
    auto entries = peb->entries();

    size_t count = 0;
    for (const auto& entry : entries) {
      if (count < 3) {
        info("    module[{}]: {} (base={}, size={})", std::to_string(count),
             entry.base_dll_name(), hex(entry.dll_base()),
             hex(entry.size_of_image()));
      }
      ++count;
    }
    info("    -> {} modules in the load order list", std::to_string(count));

    // LdrDataTableEntry::Iterator is bidirectional: step back from the
    // past-the-end position to reach the last loaded module.
    if (count > 0) {
      auto it = entries.end();
      --it;
      info("    last module (walking backwards): {}", it->base_dll_name());
    }
  }
  // lief-doc: peb-modules-end

  // lief-doc: peb-module-details-start
  if (auto peb = LIEF::runtime::windows::Process::peb()) {
    auto entries = peb->entries();
    auto it = entries.begin();
    if (it != entries.end()) {
      info("    {} extended LDR_DATA_TABLE_ENTRY fields:", it->base_dll_name());

      // Always available across the supported Windows versions:
      info("      Flags:             {}", hex(it->flags()));
      info("      ObsoleteLoadCount: {}",
           std::to_string(it->obsolete_load_count()));
      info("      TlsIndex:          {}", hex(it->tls_index()));
      info("      TimeDateStamp:     {}", hex(it->time_date_stamp()));

      // Version-gated fields: each optional is empty when the host kernel
      // predates the field, so the OS version drives what gets printed.
      if (auto v = it->ddag_node()) { // Windows 8+
        info("      DdagNode:          {}", hex(*v));
      }
      if (auto v = it->original_base()) { // Windows 8+
        info("      OriginalBase:      {}", hex(*v));
      }
      if (auto v = it->load_reason()) { // Windows 8+
        info("      LoadReason:        {}", std::to_string(*v));
      }
      if (auto v = it->signing_level()) { // Windows 10+
        info("      SigningLevel:      {}", std::to_string((uint32_t)*v));
      }
      if (auto v = it->check_sum()) { // Windows 10+
        info("      CheckSum:          {}", hex(*v));
      }
      if (auto v = it->hot_patch_state()) { // Windows 11+
        info("      HotPatchState:     {}", std::to_string(*v));
      }
    }
  }
  // lief-doc: peb-module-details-end
}

void modules_info() {
  info("Module API");
  std::unique_ptr<LIEF::runtime::windows::Module> ntdll;
  // lief-doc: modules-start
  auto mods = LIEF::runtime::modules();
  for (auto it = mods.begin(); it != mods.end(); ++it) {
    info("{}", it->to_string());
    // Look for the libc
    if (it->name().ends_with("ntdll.dll")) {
      info("ntdll.dll found: {} ([{}, {}])", it->path(), hex(it->imagebase()),
           hex(it->end()));
      // Transfer ownership so 'ntdll' outlives this loop
      std::unique_ptr<LIEF::runtime::Module> mod = it.yield();
      ntdll.reset(mod.release()->as<LIEF::runtime::windows::Module>());
    }
  }
  // lief-doc: modules-end

  if (ntdll == nullptr) {
    return;
  }

  // lief-doc: modules-windows-start
  info("ntdll path: {}", ntdll->path());
  if (void* _NtQueryInformationProcess = ntdll->dlsym("NtQueryInformationProcess"))
  {
    info("{}!NtQueryInformationProcess: {}", ntdll->name(),
         hex(reinterpret_cast<uintptr_t>(_NtQueryInformationProcess)));
  }

  if (std::unique_ptr<LIEF::PE::Binary> pe_on_disk = ntdll->parse_from_path()) {
    info("on-disk imagebase: {}", hex(pe_on_disk->optional_header().imagebase()));
    if (const LIEF::Symbol* sym =
            pe_on_disk->get_symbol("NtQueryInformationProcess"))
    {
      info("NtQueryInformationProcess: {}", hex(sym->value()));
    }
  }

  if (std::unique_ptr<LIEF::PE::Binary> pe_memory = ntdll->parse_from_memory()) {
    const uintptr_t imagebase = pe_memory->optional_header().imagebase();
    info("in-memory imagebase: {}", hex(imagebase));
    if (const LIEF::Symbol* sym = pe_memory->get_symbol("RtlFreeHeap")) {
      info("RtlFreeHeap: {}", hex(sym->value()));

      // Disassemble RtlFreeHeap from memory
      auto instructions = LIEF::runtime::disassemble(imagebase + sym->value());
      auto first_instructions = instructions | std::views::take(4);

      for (const LIEF::assembly::Instruction& inst : first_instructions) {
        info("    {}", inst.to_string());
      }
    }
  }
  // lief-doc: modules-windows-end
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

  class Config : public LIEF::assembly::AssemblerConfig {
    public:
    std::optional<uint64_t> resolve_symbol(const std::string& name) override {
      // The message to print
      static constexpr char HELLO[] = "Hello World\n";
      static constexpr uint32_t HELLO_LEN = sizeof(HELLO) - 1;

      static auto kernel32 = LIEF::runtime::windows::dlopen("kernel32.dll");

      if (kernel32 == nullptr) {
        err("Failed to dlopen kernel32.dll");
        return std::nullopt;
      }

      // Resolve the symbols that are used by the shellcode
      if (name == "GetStdHandle") {
        return reinterpret_cast<uint64_t>(kernel32->dlsym("GetStdHandle"));
      }

      if (name == "WriteFile") {
        return reinterpret_cast<uint64_t>(kernel32->dlsym("WriteFile"));
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
        stp     x29, x30, [sp, -64]!
        mov     x29, sp
        stp     x19, x20, [sp, 16]
        stp     x21, x22, [sp, 32]

        // Here we use symbols that are **dynamically** resolved by the
        // AssemblerConfig
        ldr     x19, =GetStdHandle
        ldr     x20, =WriteFile
        ldr     x21, =var_msg
        ldr     w22, =var_msg_len

        // Call GetStdHandle(STD_OUTPUT_HANDLE)
        // STD_OUTPUT_HANDLE = -11
        // GetStdHandle is stored in x19
        mov     w0, -11
        blr     x19

        // Call ---> bool WriteFile(
        //   HANDLE  hConsoleOutput,        // x0: from GetStdHandle (already set)
        //   const VOID *lpBuffer,          // x1: pointer to string
        //   DWORD   nNumberOfCharsToWrite, // w2: length of string
        //   LPDWORD lpNumberOfCharsWritten,// x3: pointer to written count
        //   LPVOID  lpReserved             // x4: NULL
        // );
        mov     x1, x21
        mov     w2, w22
        add     x3, sp, 48
        mov     x4, xzr
        blr     x20

        mov     x0, xzr
        ldp     x21, x22, [sp, 32]
        ldp     x19, x20, [sp, 16]
        ldp     x29, x30, [sp], 64
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
