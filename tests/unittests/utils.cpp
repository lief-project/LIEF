#include "utils.hpp"
#include <LIEF/logging.hpp>
#include <filesystem>

namespace fs = std::filesystem;

using namespace std::literals::string_literals;

namespace LIEF::test {
std::string get_sample_dir() {
  if (char* dir = std::getenv("LIEF_SAMPLES_DIR")) {
    fs::path path_dir(dir);
    if (fs::is_directory(path_dir)) {
      return fs::absolute(path_dir).string();
    }
    logging::log(logging::LEVEL::ERR, "'"s + path_dir.string() + "' is"
                                   " not a valid directory");
    std::exit(1);
  }
  logging::log(logging::LEVEL::ERR, "LIEF_SAMPLES_DIR not set!");
  std::exit(1);
}

std::string get_sample(const std::string& name) {
  fs::path sample_dir = get_sample_dir();
  fs::path fullpath = sample_dir / name;
  if (!fs::exists(fullpath) || !fs::is_regular_file(fullpath)) {
    logging::log(logging::LEVEL::ERR, "'"s + fullpath.string() + "' is"
                                   " does not exist");
    std::exit(1);
  }
  return fs::absolute(fullpath).string();
}

std::string get_sample(const std::string& format, const std::string& name) {
  return get_sample((fs::path(format) / name).string());
}

}
