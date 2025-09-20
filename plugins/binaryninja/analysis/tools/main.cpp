#include "log.hpp"

#include <binaryninja/binaryninjaapi.h>
#include <binaryninja/binaryninjacore.h>

#include <filesystem>

#include "binaryninja/analysis/Analyzer.hpp"

namespace bn = BinaryNinja;

namespace fs = std::filesystem;

int main(int argc, const char** argv) {
  if (argc < 2) {
    BN_ERR("Usage: {} <path>.bndb", argv[0]);
    return 1;
  }

  bn::InitPlugins();
  bn::Ref<bn::BinaryView> bv = bn::Load(argv[1], /*updateAnalysis=*/false);

  if (!bv) {
    BN_ERR("Can't load: {}", argv[1]);
    return EXIT_FAILURE;
  }

  auto analyzer = analysis_plugin::Analyzer::from_bv(*bv);
  if (analyzer == nullptr) {
    return EXIT_FAILURE;
  }

  analyzer->run();

  fs::path file_path = bv->GetFile()->GetDatabase()->GetFile()->GetFilename();
  std::string filename = file_path.filename().string();
  fs::path new_bndb = file_path.parent_path() / ("updated_" + filename);

  bv->CreateDatabase(new_bndb.generic_string());

  bv->GetFile()->Close();
  BNShutdown();

  return 0;
}
