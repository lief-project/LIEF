#include <LIEF/LIEF.hpp>

int main(int argc, const char** argv) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <binary>" << '\n';
    return EXIT_FAILURE;
  }
  LIEF::MachO::ParserConfig config;
  config.parse_dyld_rebases = false;
  config.parse_dyld_exports = false;
  config.parse_dyld_bindings = false;
  auto binary = LIEF::MachO::Parser::parse(argv[1], config);
  return EXIT_SUCCESS;
}
