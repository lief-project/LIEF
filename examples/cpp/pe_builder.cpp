/* PE binary modification and rebuild.
 *
 * Demonstrates how to parse a PE binary, make modifications (add a section,
 * modify DLL characteristics, add an import), and write the result.
 *
 * Usage: ./pe_builder <input_binary> <output_binary>
 */

#include <iostream>
#include <memory>
#include <vector>

#include <LIEF/PE.hpp>

using namespace LIEF::PE;

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " <Input Binary> <Output Binary>\n";
    return EXIT_FAILURE;
  }

  auto binary = Parser::parse(argv[1]);
  if (binary == nullptr) {
    std::cerr << "Failed to parse: " << argv[1] << "\n";
    return EXIT_FAILURE;
  }

  // Add a new section with custom data
  Section new_section(".lief");
  new_section.add_characteristic(Section::CHARACTERISTICS::MEM_READ);
  new_section.add_characteristic(Section::CHARACTERISTICS::CNT_INITIALIZED_DATA);
  std::vector<uint8_t> content = {'L', 'I', 'E', 'F'};
  new_section.content(content);
  binary->add_section(new_section);

  // Enable ASLR if not already enabled
  auto& opt = binary->optional_header();
  if (!opt.has(OptionalHeader::DLL_CHARACTERISTICS::DYNAMIC_BASE)) {
    opt.add(OptionalHeader::DLL_CHARACTERISTICS::DYNAMIC_BASE);
    std::cout << "Enabled ASLR (DYNAMIC_BASE)\n";
  }

  // Enable NX/DEP if not already enabled
  if (!opt.has(OptionalHeader::DLL_CHARACTERISTICS::NX_COMPAT)) {
    opt.add(OptionalHeader::DLL_CHARACTERISTICS::NX_COMPAT);
    std::cout << "Enabled DEP (NX_COMPAT)\n";
  }

  // Write the modified binary
  Builder::config_t config;
  binary->write(argv[2], config);

  std::cout << "Modified binary written to: " << argv[2] << "\n";
  return EXIT_SUCCESS;
}
