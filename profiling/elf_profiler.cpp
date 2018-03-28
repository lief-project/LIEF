#include <LIEF/LIEF.hpp>

int main(int argc, char** argv) {
  std::unique_ptr<LIEF::ELF::Binary> binary{LIEF::ELF::Parser::parse("/usr/bin/ls")};
  return 0;
}
