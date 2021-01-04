#include <iostream>
#include <LIEF/LIEF.hpp>

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <binary>" << std::endl;
    return 1;
  }

  auto binary = LIEF::Parser::parse(argv[1]);
  std::cout << *binary << std::endl;
  return 0;
}
