#include <link.h>
#include <LIEF/ELF.hpp>
#include <iostream>
#include <sstream>

using namespace LIEF::ELF;

void dump(void) {

  std::unique_ptr<Binary> core = Binary::create_lief_core(LIEF::ELF::ARCH::EM_X86_64);

  dl_iterate_phdr([] (dl_phdr_info* info, size_t size, void* data) {
    Binary* core = reinterpret_cast<Binary*>(data);

    if (info->dlpi_name == nullptr) {
      return 0;
    }

    for (size_t i = 0; i < info->dlpi_phnum; ++i) {

      std::ostringstream oss;
      oss << "." << info->dlpi_name << "." << std::dec << i;
      Section section{oss.str()};
      const uint8_t* start = reinterpret_cast<uint8_t*>(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
      const uint8_t* stop = start + info->dlpi_phdr[i].p_memsz;
      //std::cout << std::showbase << std::hex << info->dlpi_addr + info->dlpi_phdr[i].p_vaddr << std::endl;
      section.content({start, stop});

      Section& added = core->add(section, true);

      added.virtual_address(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
    }

    std::cout << info->dlpi_name << std::endl;
    return 0;
  }, core.get());
  core->write("/tmp/bar");
}


int main(int argc, char** argv) {
  dump();
  return 0;
}
