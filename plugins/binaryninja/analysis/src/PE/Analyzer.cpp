/* Copyright 2025 - 2026 R. Thomas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "binaryninja/analysis/PE/Analyzer.hpp"
#include "log.hpp"
#include "binaryninja/analysis/PE/TypeBuilder.hpp"

#include "binaryninja/analysis/PE/analyzers/LoadConfiguration.hpp"
#include "binaryninja/analysis/PE/analyzers/RuntimeFunctions.hpp"

#include <binaryninja/binaryninjaapi.h>
#include <binaryninja/binaryninjacore.h>

using namespace LIEF;
using namespace BinaryNinja;

namespace analysis_plugin::pe {

Analyzer::Analyzer(std::unique_ptr<LIEF::PE::Binary> impl,
                   BinaryNinja::BinaryView& bv) :
  analysis_plugin::Analyzer(bv, std::make_unique<TypeBuilder>(bv)),
  pe_(std::move(impl))
{
  using namespace analyzers;

  if (RuntimeFunctions::can_run(*bv_, *pe_)) {
    analyzers_.push_back(std::make_unique<RuntimeFunctions>(
      *bv_, *pe_, static_cast<pe::TypeBuilder&>(*type_builder_)
    ));
  }

  if (LoadConfiguration::can_run(*bv_, *pe_)) {
    analyzers_.push_back(std::make_unique<LoadConfiguration>(
        *bv_, *pe_, static_cast<pe::TypeBuilder&>(*type_builder_)
    ));
  }
}

std::unique_ptr<Analyzer> Analyzer::from_bv(BinaryNinja::BinaryView& bv) {
  static const PE::ParserConfig CONFIG = PE::ParserConfig::all();

  std::string filename = bv.GetFile()->GetOriginalFilename();

  std::unique_ptr<PE::Binary> pe = PE::Parser::parse(filename, CONFIG);
  if (pe == nullptr) {
    BN_ERR("Can't parse '{}'", filename);
    return nullptr;
  }

  return std::make_unique<Analyzer>(std::move(pe), bv);
}

void Analyzer::run() {
  for (const std::unique_ptr<AnalyzerBase>& analyzer : analyzers_) {
    analyzer->run();
  }
}

}
