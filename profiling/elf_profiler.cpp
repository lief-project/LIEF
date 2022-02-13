#include <LIEF/LIEF.hpp>

int main(int argc, const char** argv) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <binary>" << '\n';
    return EXIT_FAILURE;
  }
  std::unique_ptr<LIEF::ELF::Binary> binary = LIEF::ELF::Parser::parse(argv[1]);
  return EXIT_SUCCESS;
}
