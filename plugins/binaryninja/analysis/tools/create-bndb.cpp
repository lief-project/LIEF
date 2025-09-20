#include "log.hpp"

#include <binaryninja/binaryninjaapi.h>
#include <binaryninja/binaryninjacore.h>
#include "binaryninja/lief_utils.hpp"

#include "binaryninja/analysis/Analyzer.hpp"

namespace bn = BinaryNinja;

int main(int argc, const char** argv) {
  if (argc < 3) {
    BN_ERR("Usage: {} <target> <output>", argv[0]);
    return 1;
  }

  std::string target = argv[1];
  std::string output = argv[2];

  bn::InitPlugins();
  bn::Ref<bn::BinaryView> bv = bn::Load(target, /*updateAnalysis=*/true);

  if (!bv) {
    BN_ERR("Can't load: {}", argv[1]);
    return EXIT_FAILURE;
  }

  bv->CreateDatabase(output);
  bv->GetFile()->Close();

  BNShutdown();

  return EXIT_SUCCESS;
}
