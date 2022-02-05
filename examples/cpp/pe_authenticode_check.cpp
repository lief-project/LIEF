
#include <iostream>
#include <memory>

#include <LIEF/PE.hpp>
#include <LIEF/logging.hpp>

using namespace LIEF::PE;

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <PE binary>" << "\n";
    return 1;
  }
  std::unique_ptr<const Binary> binary = Parser::parse(argv[1]);
  if (binary->verify_signature() != Signature::VERIFICATION_FLAGS::OK) {
    std::cerr << "Signature failed!\n";
    return 1;
  }
  std::cout << "Signature ok!\n";
  return 0;
}
