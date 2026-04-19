#include <LIEF/LIEF.hpp>
#include <filesystem>

void process_file(const std::filesystem::path& target) {
  auto binary = LIEF::MachO::Parser::parse(target.string(),
                                           LIEF::MachO::ParserConfig::deep());
}

void process_dir(const std::filesystem::path& target) {
  for (const auto& e : std::filesystem::directory_iterator(target)) {
    if (e.is_directory()) {
      process_dir(e.path());
    } else if (e.is_regular_file() && LIEF::MachO::is_macho(e.path().string())) {
      process_file(e.path());
    }
  }
}

int main(int /*argc*/, const char** argv) {
  const std::filesystem::path target{argv[1]};
  if (std::filesystem::is_directory(target)) {
    process_dir(target);
  } else {
    process_file(target);
  }
  return EXIT_SUCCESS;
}
