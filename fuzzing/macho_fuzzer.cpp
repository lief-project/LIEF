#include <LIEF/LIEF.hpp>
#include <vector>
#include <memory>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::vector<uint8_t> raw = {data, data + size};
  std::unique_ptr<LIEF::MachO::FatBinary> binaries;
  try {
     binaries = std::unique_ptr<LIEF::MachO::FatBinary>(LIEF::MachO::Parser::parse(raw));
  } catch (const LIEF::exception& e) {
    std::cout << e.what() << std::endl;
  }
  return 0;
}
