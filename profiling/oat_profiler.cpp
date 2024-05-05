#include <LIEF/LIEF.hpp>
#include <iostream>

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <oat>" << '\n';
  }
  std::unique_ptr<LIEF::OAT::Binary> binary{LIEF::OAT::Parser::parse(argv[1])};
  return 0;
}
