#include <LIEF/ObjC.hpp>
#include <LIEF/MachO.hpp>
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
    log(LEVEL::ERR, "Usage: {} <macho file>", argv[0]);
    return EXIT_FAILURE;
  }

  set_level(LEVEL::INFO);
  std::unique_ptr<LIEF::MachO::FatBinary> fat = LIEF::MachO::Parser::parse(argv[1]);
  if (!fat) {
    return EXIT_FAILURE;
  }
  LIEF::MachO::Binary* bin = fat->at(0);
  if (!bin) {
    return EXIT_FAILURE;
  }

  std::unique_ptr<LIEF::objc::Metadata> metadata = bin->objc_metadata();
  if (!metadata) {
    return EXIT_FAILURE;
  }

  for (const std::unique_ptr<LIEF::objc::Class>& clazz : metadata->classes()) {
    log(LOG_LVL, "name={}", clazz->name());
    for (const std::unique_ptr<LIEF::objc::Method>& meth : clazz->methods()) {
      log(LOG_LVL, "  method.name={}", meth->name());
    }
  }

  log(LOG_LVL, metadata->to_decl());


  return EXIT_SUCCESS;
}
