#include "LIEF/PE/signature/SignatureParser.hpp"
#include "LIEF/logging.hpp"

__attribute__((constructor)) void foo(){
  LIEF::logging::disable();
}

LIEF_API extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  LIEF::PE::SignatureParser::parse(std::vector<uint8_t>{data, data + size});
  return 0;  // Non-zero return values are reserved for future use.
}

