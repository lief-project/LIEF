#include "utils.hpp"
#include <catch2/catch_test_macros.hpp>
#include <filesystem>

namespace fs = std::filesystem;

namespace LIEF::test {
std::string get_sample_dir() {
  if (char* dir = std::getenv("LIEF_SAMPLES_DIR")) {
    fs::path path_dir(dir);
    if (fs::is_directory(path_dir)) {
      return fs::absolute(path_dir).string();
    }
    FAIL("'" << path_dir.string() << "' is not a valid directory");
  }
  FAIL("LIEF_SAMPLES_DIR not set!");
}

std::string get_sample(const std::string& name) {
  fs::path sample_dir = get_sample_dir();
  fs::path fullpath = sample_dir / name;
  if (!fs::exists(fullpath) || !fs::is_regular_file(fullpath)) {
    FAIL("'" << fullpath.string() << "' does not exist");
  }
  return fs::absolute(fullpath).string();
}

std::string get_sample(const std::string& format, const std::string& name) {
  return get_sample((fs::path(format) / name).string());
}

}
