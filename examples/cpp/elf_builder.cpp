/* ELF binary modification and rebuild.
 *
 * Demonstrates how to parse an ELF binary, make modifications (add a section,
 * add an exported symbol, change library search paths), and write the result.
 *
 * Usage: ./elf_builder <input_binary> <output_binary>
 */

#include <iostream>
#include <memory>
#include <vector>

#include <LIEF/ELF.hpp>

using namespace LIEF::ELF;

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " <Input Binary> <Output Binary>\n";
    return 1;
  }

  auto binary = Parser::parse(argv[1]);
  if (binary == nullptr) {
    std::cerr << "Failed to parse: " << argv[1] << "\n";
    return 1;
  }

  // Add a new data section with custom content
  Section new_section(".lief");
  new_section.type(Section::TYPE::PROGBITS);
  new_section.add(Section::FLAGS::ALLOC);
  std::vector<uint8_t> content = {'L', 'I', 'E', 'F'};
  new_section.content(content);
  binary->add(new_section);

  // Modify RUNPATH to add a custom library search directory
  for (DynamicEntry& entry : binary->dynamic_entries()) {
    if (auto* runpath = entry.cast<DynamicEntryRunPath>()) {
      std::string current = runpath->runpath();
      if (!current.empty()) {
        current += ':';
      }
      runpath->runpath(current + "/opt/custom/lib");
      std::cout << "Updated RUNPATH: " << runpath->runpath() << "\n";
      break;
    }
  }

  // Write the modified binary with relocation support
  Builder::config_t config;
  config.force_relocate = true;
  binary->write(argv[2], config);

  std::cout << "Modified binary written to: " << argv[2] << "\n";
  return 0;
}
