#include <LIEF/runtime/Module.hpp>

#include <cstdint>

extern "C" __attribute__((visibility("default"))) uint64_t
    lief_current_module_imagebase() {
  std::unique_ptr<LIEF::runtime::Module> mod = LIEF::runtime::current_module();
  if (mod == nullptr) {
    return 0;
  }
  return mod->imagebase();
}
