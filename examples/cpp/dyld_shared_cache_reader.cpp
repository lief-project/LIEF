#include <LIEF/DyldSharedCache.hpp>
#include <LIEF/logging.hpp>
#include <LIEF/utils.hpp>

#include <cstdlib>

using namespace LIEF::logging;

static constexpr auto LOG_LVL = LEVEL::INFO;

int main(int argc, const char** argv) {
  if (!LIEF::is_extended()) {
    log(LEVEL::ERR, "This example requires the extended version of LIEF");
    return EXIT_FAILURE;
  }

  if (argc != 2) {
    log(LEVEL::ERR, "Usage: {} <shared-cache>", argv[0]);
    return EXIT_FAILURE;
  }

  set_level(LEVEL::INFO);
  std::unique_ptr<LIEF::dsc::DyldSharedCache> dyld_cache = LIEF::dsc::load(argv[1]);
  if (dyld_cache == nullptr) {
    log(LEVEL::ERR, "Can't read {} as a shared cache file", argv[0]);
    return EXIT_FAILURE;
  }

  for (std::unique_ptr<LIEF::dsc::Dylib> lib : dyld_cache->libraries()) {
    log(LOG_LVL, "{}: {}", std::to_string(lib->address()), lib->path());
  }

  return EXIT_SUCCESS;
}
