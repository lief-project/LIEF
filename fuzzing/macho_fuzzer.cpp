#include <LIEF/LIEF.hpp>
#include <vector>
#include <memory>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::vector<uint8_t> raw = {data, data + size};
  std::vector<LIEF::MachO::Binary*> binaries;
  try {
     binaries = LIEF::MachO::Parser::parse(raw);
  } catch (const LIEF::exception& e) {
    std::cout << e.what() << std::endl;
  }
  for (LIEF::MachO::Binary* b: binaries) {
    delete b;
  }
  return 0;
}
