#include <LIEF/LIEF.hpp>
#include <LIEF/BinaryStream/SpanStream.hpp>
#include <memory>
#include <sstream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  auto stream = std::make_unique<LIEF::SpanStream>(data, size);
  if (auto b = LIEF::ELF::Parser::parse(std::move(stream))) {
    std::stringstream oss;
    oss << *b;
  }
  return 0;
}
