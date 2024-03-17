#include <iostream>
#include <LIEF/LIEF.hpp>

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <binary>" << '\n';
    return 1;
  }

  if (auto binary = LIEF::Parser::parse(argv[1])) {
    std::cout << *binary << '\n';
  }
  return 0;
}
