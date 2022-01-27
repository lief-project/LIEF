#include "LIEF/ELF.hpp"
#include "LIEF/PE.hpp"
#include "LIEF/MachO.hpp"
#include "logging.hpp"
#include <sstream>

void check(LIEF::PE::Binary& bin) {
  std::stringstream ss;
  ss << bin;
}

void check(LIEF::MachO::FatBinary& bin) {
  std::stringstream ss;
  for (const LIEF::MachO::Binary& fit : bin) {
    ss << fit;
  }
}

void check(LIEF::ELF::Binary& bin) {
  std::stringstream ss;
  ss << bin;
}

int main(int argc, char** argv) {
  //int k = 0x7fffffff;
  //k += argc;
  if (argc != 2) {
    LIEF_ERR("Usage: {} <binary>", argv[0]);
    return EXIT_FAILURE;
  }
  const std::string path = argv[1];
  if (LIEF::ELF::is_elf(path)) {
    std::unique_ptr<LIEF::ELF::Binary> bin = LIEF::ELF::Parser::parse(path);
    check(*bin);
  }
  else if (LIEF::PE::is_pe(path)) {
    std::unique_ptr<LIEF::PE::Binary> bin = LIEF::PE::Parser::parse(path);
    check(*bin);
  }
  else if (LIEF::MachO::is_macho(path)) {
    std::unique_ptr<LIEF::MachO::FatBinary> bin = LIEF::MachO::Parser::parse(path);
    check(*bin);
  }
  return EXIT_SUCCESS;
}
