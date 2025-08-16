/* Copyright 2025 R. Thomas
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
#include "Analyzer.hpp"
#include "log.hpp"
#include "TypeBuilder.hpp"

#include <binaryninja/binaryninjaapi.h>
#include <binaryninja/binaryninjacore.h>

#include "analyzers/AndroidPackedRelocations.hpp"
#include "analyzers/Relocations.hpp"
#include "analyzers/RelativeRelocations.hpp"

using namespace LIEF;

namespace analysis_plugin::elf {
Analyzer::Analyzer(std::unique_ptr<LIEF::ELF::Binary> impl, BinaryNinja::BinaryView& bv) :
  analysis_plugin::Analyzer(bv, std::make_unique<TypeBuilder>(bv)),
  elf_(std::move(impl))
{
  using namespace analyzers;

  if (Relocations::can_run(*bv_, *elf_)) {
    analyzers_.push_back(std::make_unique<Relocations>(
      *bv_, *elf_, static_cast<elf::TypeBuilder&>(*type_builder_)
    ));
  }

  if (AndroidPackedRelocations::can_run(*bv_, *elf_)) {
    analyzers_.push_back(std::make_unique<AndroidPackedRelocations>(
      *bv_, *elf_, static_cast<elf::TypeBuilder&>(*type_builder_)
    ));
  }

  if (RelativeRelocations::can_run(*bv_, *elf_)) {
    analyzers_.push_back(std::make_unique<RelativeRelocations>(
      *bv_, *elf_, static_cast<elf::TypeBuilder&>(*type_builder_)
    ));
  }
}

std::unique_ptr<Analyzer> Analyzer::from_bv(BinaryNinja::BinaryView& bv) {
  static const ELF::ParserConfig CONFIG = ELF::ParserConfig::all();
  std::string filename = bv.GetFile()->GetOriginalFilename();

  std::unique_ptr<ELF::Binary> elf = ELF::Parser::parse(filename, CONFIG);
  if (elf == nullptr) {
    BN_ERR("Can't parse '{}'", filename);
    return nullptr;
  }

  return std::make_unique<Analyzer>(std::move(elf), bv);
}

void Analyzer::run() {
  for (const std::unique_ptr<AnalyzerBase>& analyzer : analyzers_) {
    analyzer->run();
  }
}

}
