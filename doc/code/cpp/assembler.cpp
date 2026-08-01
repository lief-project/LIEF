#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <LIEF/Abstract/Binary.hpp>
#include <LIEF/ELF.hpp>
#include <LIEF/asm/AssemblerConfig.hpp>
#include <LIEF/asm/Instruction.hpp>
#include <optional>

void disassemble_assemble() {
  // lief-doc: disassemble-assemble-start
  std::unique_ptr<LIEF::ELF::Binary> elf;

  std::vector<uint64_t> syscall_addresses;
  for (const auto& inst : elf->disassemble(0x400090)) {
    if (inst.is_syscall()) {
      syscall_addresses.push_back(inst.address());
    }
  }

  for (uint64_t addr : syscall_addresses) {
    elf->assemble(addr, R"asm(
      mov x1, x0;
      str x1, [x2, #8];
    )asm");
  }
  // lief-doc: disassemble-assemble-end
}

void context_error() {
  // lief-doc: context-error-start
  std::unique_ptr<LIEF::ELF::Binary> elf;
  elf->assemble(elf->entrypoint(), R"asm(
    mov rdi, rax;
    call a_custom_function;
  )asm");
  // lief-doc: context-error-end
}

void config_resolver() {
  // lief-doc: config-resolver-start
  class MyConfig : public LIEF::assembly::AssemblerConfig {
    public:
    std::optional<uint64_t> resolve_symbol(const std::string& name) override {
      if (name == "a_custom_function") {
        return 0x1000;
      }
      return std::nullopt;
    }
  };

  MyConfig myconfig;

  std::unique_ptr<LIEF::ELF::Binary> elf;

  elf->assemble(elf->entrypoint(), R"asm(
    mov rdi, rax;
    call a_custom_function;
  )asm",
                myconfig);
  // lief-doc: config-resolver-end
}

void config_target() {
  // lief-doc: config-target-start
  class MyConfig : public LIEF::assembly::AssemblerConfig {
    public:
    MyConfig() = delete;
    MyConfig(LIEF::Binary& target) :
      LIEF::assembly::AssemblerConfig(),
      target_(&target) {}

    std::optional<uint64_t> resolve_symbol(const std::string& name) override {
      if (auto addr = target_->get_function_address(name)) {
        return *addr;
      }
      return std::nullopt;
    }

    ~MyConfig() override = default;

    private:
    LIEF::Binary* target_ = nullptr;
  };

  std::unique_ptr<LIEF::ELF::Binary> elf;
  MyConfig myconfig(*elf);

  elf->assemble(elf->entrypoint(), R"asm(
    mov rdi, rax;
    call a_custom_function;
  )asm",
                myconfig);
  // lief-doc: config-target-end
}

void disable_instruction() {
  // lief-doc: nop-out-start
  std::unique_ptr<LIEF::ELF::Binary> elf;

  // Overwrite the first call in the region (e.g. a call to an anti-debugging
  // routine) with nops
  for (const auto& inst : elf->disassemble(0x401200)) {
    if (inst.is_call()) {
      std::string nops;
      for (size_t i = 0; i < inst.size(); ++i) {
        nops += "nop\n";
      }
      elf->assemble(inst.address(), nops);
      break;
    }
  }

  elf->write("patched.bin");
  // lief-doc: nop-out-end
}
