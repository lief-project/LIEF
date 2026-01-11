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
#include "binaryninja/analysis/MachO/Analyzer.hpp"
#include "log.hpp"
#include "binaryninja/analysis/MachO/TypeBuilder.hpp"

#include <binaryninja/binaryninjaapi.h>
#include <binaryninja/binaryninjacore.h>

using namespace LIEF;

namespace analysis_plugin::macho {

using namespace BinaryNinja;

static std::unique_ptr<MachO::Binary>
  get_matching_macho(MachO::FatBinary& fat, BinaryNinja::BinaryView& bv)
{
  if (fat.size() == 1) {
    return fat.take(0);
  }

  Ref<Architecture> arch = bv.GetDefaultArchitecture();
  const std::string arch_name = arch->GetName();

  if (arch_name == "aarch64") {
    return fat.take(LIEF::MachO::Header::CPU_TYPE::ARM64);
  }

  if (arch_name == "armv7" || arch_name == "thumb2") {
    return fat.take(LIEF::MachO::Header::CPU_TYPE::ARM);
  }

  if (arch_name == "x86_64") {
    return fat.take(LIEF::MachO::Header::CPU_TYPE::X86_64);
  }

  if (arch_name == "x86") {
    return fat.take(LIEF::MachO::Header::CPU_TYPE::X86);
  }

  if (arch_name == "ppc") {
    return fat.take(LIEF::MachO::Header::CPU_TYPE::POWERPC);
  }

  if (arch_name == "ppc64") {
    return fat.take(LIEF::MachO::Header::CPU_TYPE::POWERPC64);
  }

  BN_ERR("Unsupported architecture: {} ({})",
         arch_name, bv.GetDefaultPlatform()->GetName());
  return nullptr;
}

Analyzer::Analyzer(std::unique_ptr<LIEF::MachO::Binary> impl, BinaryNinja::BinaryView& bv) :
  analysis_plugin::Analyzer(bv, std::make_unique<TypeBuilder>(bv)),
  macho_(std::move(impl))
{}

std::unique_ptr<Analyzer> Analyzer::from_bv(BinaryNinja::BinaryView& bv) {
  static const MachO::ParserConfig CONFIG = MachO::ParserConfig::deep();

  std::string original_file = bv.GetFile()->GetOriginalFilename();

  std::unique_ptr<LIEF::MachO::FatBinary> fat = LIEF::MachO::Parser::parse(original_file);
  if (fat == nullptr) {
    BN_ERR("Can't parse '{}'", original_file);
    return nullptr;
  }

  std::unique_ptr<MachO::Binary> bin = get_matching_macho(*fat, bv);
  if (bin == nullptr) {
    BN_ERR("Can't get MachO binary matching  architecture: '{}'",
        bv.GetDefaultArchitecture()->GetName());
    return nullptr;
  }
  return std::make_unique<Analyzer>(std::move(bin), bv);
}

void Analyzer::run() {

}
}
