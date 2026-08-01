#include <LIEF/LIEF.hpp>
#include <memory>
#include <sstream>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::vector<uint8_t> raw = {data, data + size};
  if (auto b = LIEF::Parser::parse(raw)) {
    std::stringstream oss;
    oss << *b;
  }
  return 0;
}
