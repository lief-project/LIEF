#include "log.hpp"

#include <binaryninja/binaryninjaapi.h>
#include <binaryninja/binaryninjacore.h>
#include "binaryninja/lief_utils.hpp"

#include "binaryninja/analysis/Analyzer.hpp"

namespace bn = BinaryNinja;

int main(int argc, const char** argv) {
  if (argc < 4) {
    BN_ERR("Usage: {} <path>.bndb <original> <updated>", argv[0]);
    return 1;
  }

  std::string original_out = argv[2];
  std::string updated_out = argv[3];

  bn::InitPlugins();
  bn::Ref<bn::BinaryView> bv = bn::Load(argv[1], /*updateAnalysis=*/false);

  binaryninja::linear_export(*bv, original_out);

  if (!bv) {
    BN_ERR("Can't load: {}", argv[1]);
    return EXIT_FAILURE;
  }

  auto analyzer = analysis_plugin::Analyzer::from_bv(*bv);
  if (analyzer == nullptr) {
    return EXIT_FAILURE;
  }

  analyzer->run();

  binaryninja::linear_export(*bv, updated_out);

  bv->GetFile()->Close();
  BNShutdown();

  return EXIT_SUCCESS;
}
