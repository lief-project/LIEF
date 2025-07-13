#include <cxxgen.h>

#include "LIEF/rust/asm/AssemblerConfig.hpp"

#include <memory>

class RustAssemblerConfig : public LIEF::assembly::AssemblerConfig {
  public:
  RustAssemblerConfig(const AssemblerConfig_r& impl) :
    LIEF::assembly::AssemblerConfig(),
    impl_(const_cast<AssemblerConfig_r*>(&impl))
  {}

  LIEF::optional<uint64_t> resolve_symbol(const std::string& name) override {
    int64_t addr = impl_->resolve_symbol(name);
    if (addr < 0) {
      return LIEF::nullopt();
    }
    return addr;
  }

  ~RustAssemblerConfig() override = default;

  protected:
  AssemblerConfig_r* impl_ = nullptr;
};

std::unique_ptr<LIEF::assembly::AssemblerConfig> from_rust(const AssemblerConfig_r& config) {
  return std::make_unique<RustAssemblerConfig>(config);
}
