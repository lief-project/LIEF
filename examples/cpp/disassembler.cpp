#include <LIEF/LIEF.hpp>

using namespace LIEF::logging;

int main(int argc, const char** argv) {
  if (!LIEF::is_extended()) {
    err("This example requires the extended version of LIEF");
    return EXIT_FAILURE;
  }

  if (argc != 3) {
    err("Usage: {} <binary> <address>", argv[0]);
    return EXIT_FAILURE;
  }

  std::unique_ptr<LIEF::Binary> target = LIEF::Parser::parse(argv[1]);

  if (target == nullptr) {
    err("Can't parse: {}", argv[1]);
    return EXIT_FAILURE;
  }

  std::string add_str = argv[2];
  uint64_t addr = 0;

  if (add_str.size() > 2 && add_str[0] == '0' && add_str[1] == 'x') {
    addr = std::strtoull(add_str.c_str() + 2, /*__endptr=*/nullptr, 16);
  } else {
    addr = std::strtoull(add_str.c_str(), /*__endptr=*/nullptr, 10);
  }

  for (std::unique_ptr<LIEF::assembly::Instruction> inst : target->disassemble(addr)) {
    info("{}", inst->to_string());
  }

  return EXIT_SUCCESS;
}
