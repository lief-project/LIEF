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
#include "log.hpp"
#include "binaryninja/analysis/Analyzer.hpp"

#include "binaryninja/analysis/PE/Analyzer.hpp"
#include "binaryninja/analysis/ELF/Analyzer.hpp"
#include "binaryninja/analysis/MachO/Analyzer.hpp"
#include "binaryninja/analysis/COFF/Analyzer.hpp"
#include "binaryninja/analysis/DSC/Analyzer.hpp"

#include "binaryninja/lief_utils.hpp"

#include <binaryninja/binaryninjaapi.h>
#include <binaryninja/binaryninjacore.h>

using namespace LIEF;
using namespace binaryninja;

namespace analysis_plugin {

Analyzer::Analyzer(BinaryNinja::BinaryView& bv, std::unique_ptr<TypeBuilder> ty_builder) :
  bv_(&bv), type_builder_(std::move(ty_builder))
{}

std::unique_ptr<Analyzer> Analyzer::from_bv(BinaryNinja::BinaryView& bv) {
  const FileFormat file_format = get_file_format(bv);
  switch (file_format) {
    case FileFormat::PE:
      return pe::Analyzer::from_bv(bv);

    case FileFormat::ELF:
      return elf::Analyzer::from_bv(bv);

    case FileFormat::MachO:
      return macho::Analyzer::from_bv(bv);

    case FileFormat::COFF:
      return coff::Analyzer::from_bv(bv);

    case FileFormat::DSC:
      return dsc::Analyzer::from_bv(bv);

    case FileFormat::Unknown:
      BN_ERR("Unknown format for {}", bv.GetFile()->GetFilename());
      return nullptr;
  }
}

Analyzer::~Analyzer() = default;
}

