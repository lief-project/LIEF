#include "log.hpp"

#include "binaryninja/lief_utils.hpp"
#include <binaryninja/binaryninjaapi.h>
#include <binaryninja/binaryninjacore.h>

#include "binaryninja/analysis/Analyzer.hpp"

namespace BN = BinaryNinja;

int main(int argc, const char** argv) {
  if (argc < 3) {
    BN_ERR("Usage: {} <target> <output>", argv[0]);
    return 1;
  }

  std::string target = argv[1];
  std::string output = argv[2];

  BN::InitPlugins();
  BN::Ref<BN::BinaryView> bv = BN::Load(target, /*updateAnalysis=*/true);

  if (!bv) {
    BN_ERR("Can't load: {}", argv[1]);
    return EXIT_FAILURE;
  }

  bv->CreateDatabase(output);
  bv->GetFile()->Close();

  BNShutdown();

  return EXIT_SUCCESS;
}
