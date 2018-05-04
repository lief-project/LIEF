#include <LIEF/LIEF.hpp>

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <oat>" << std::endl;
  }
  std::unique_ptr<LIEF::OAT::Binary> binary{LIEF::OAT::Parser::parse(argv[1])};
  return 0;
}
