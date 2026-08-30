#include <unordered_map>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include <LIEF/runtime.hpp>

void iterate() {
  // lief-doc: iterate-start
  for (const LIEF::runtime::MemoryLayout::Region& region :
       LIEF::runtime::memory_layout())
  {
    std::cout << region.addr() << '-' << region.end_addr() << ' ' << region.name()
              << '\n';
  }
  // lief-doc: iterate-end
}

void inspect(uint64_t address) {
  // lief-doc: inspect-start
  size_t count = 0;
  uint64_t mapped = 0;
  std::unordered_map<std::string, uint64_t> footprint;
  LIEF::runtime::MemoryLayout::Region enclosing;

  for (const LIEF::runtime::MemoryLayout::Region& region :
       LIEF::runtime::memory_layout())
  {
    ++count;
    mapped += region.size();

    std::string name =
        region.name().empty() ? "<anonymous>" : std::string(region.name());

    footprint[name] += region.size();

    if (region.contains(address)) {
      enclosing = region;
    }
  }

  std::cout << count << " regions, " << (mapped / 1024) << " KB mapped\n";

  for (const auto& [name, size] : footprint) {
    std::cout << size << ' ' << name << '\n';
  }

  if (enclosing.size() > 0) {
    std::cout << address << ": " << enclosing.name() << '+'
              << (address - enclosing.addr()) << '\n';
  }
  // lief-doc: inspect-end
}

void stack_and_heap() {
  // lief-doc: stack-heap-start
  for (const LIEF::runtime::MemoryLayout::Region& region :
       LIEF::runtime::memory_layout())
  {
    // On Linux and Android, the kernel names the regions that back the stack
    // and the heap of the process.
    if (region.name() == "[stack]" || region.name() == "[heap]") {
      std::cout << region.name() << ": " << region.addr() << '-'
                << region.end_addr() << '\n';
    }
  }
  // lief-doc: stack-heap-end
}
