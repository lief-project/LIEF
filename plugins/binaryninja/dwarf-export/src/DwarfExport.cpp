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
#include <binaryninja/binaryninjaapi.h>
#include <binaryninja/binaryninjacore.h>

#include <LIEF/MachO/utils.hpp>
#include <LIEF/MachO/Parser.hpp>
#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/FatBinary.hpp>
#include <LIEF/MachO/Header.hpp>
#include <LIEF/ELF/utils.hpp>
#include <LIEF/PE/utils.hpp>

#include <LIEF/utils.hpp>
#include <LIEF/DWARF/Editor.hpp>
#include <LIEF/DWARF/editor/CompilationUnit.hpp>
#include <LIEF/DWARF/editor/Function.hpp>
#include <LIEF/DWARF/editor/Variable.hpp>

#include <LIEF/Abstract/Binary.hpp>
#include <LIEF/Abstract/Parser.hpp>

#include "DwarfExport.hpp"
#include "FunctionEngine.hpp"
#include "VarEngine.hpp"
#include "TypeEngine.hpp"
#include "log.hpp"

namespace bn = BinaryNinja;

namespace dw = LIEF::dwarf::editor;

namespace dwarf_plugin {

DwarfExport::~DwarfExport() = default;

DwarfExport::DwarfExport(BinaryNinja::BinaryView& bv) :
  bv_{&bv}
{}

std::unique_ptr<LIEF::Binary> get_bin(bn::BinaryView& bv) {
  std::string original_file = bv.GetFile()->GetOriginalFilename();
  if (LIEF::MachO::is_macho(original_file)) {
    bn::Ref<bn::Architecture> arch = bv.GetDefaultArchitecture();
    std::unique_ptr<LIEF::MachO::FatBinary> fat = LIEF::MachO::Parser::parse(original_file);
    if (fat == nullptr) {
      return nullptr;
    }

    if (fat->size() == 1) {
      return fat->take(0);
    }

    const std::string arch_name = arch->GetName();
    if (arch_name == "aarch64") {
      return fat->take(LIEF::MachO::Header::CPU_TYPE::ARM64);
    }

    if (arch_name == "armv7" || arch_name == "thumb2") {
      return fat->take(LIEF::MachO::Header::CPU_TYPE::ARM);
    }

    if (arch_name == "x86_64") {
      return fat->take(LIEF::MachO::Header::CPU_TYPE::X86_64);
    }

    if (arch_name == "x86") {
      return fat->take(LIEF::MachO::Header::CPU_TYPE::X86);
    }

    if (arch_name == "ppc") {
      return fat->take(LIEF::MachO::Header::CPU_TYPE::POWERPC);
    }

    if (arch_name == "ppc64") {
      return fat->take(LIEF::MachO::Header::CPU_TYPE::POWERPC64);
    }

    BN_ERR("Unsupported architecture: {} ({})",
           arch_name, bv.GetDefaultPlatform()->GetName());
    return nullptr;
  }

  return LIEF::Parser::parse(original_file);
}

dw::CompilationUnit* DwarfExport::create() {
  bin_ = get_bin(*bv_);
  if (bin_ == nullptr) {
    BN_WARN("Can't parse {} with LIEF", bv_->GetFile()->GetOriginalFilename());
    return nullptr;
  }

  editor_ = LIEF::dwarf::Editor::from_binary(*bin_);
  if (editor_ == nullptr) {
    return nullptr;
  }
  unit_ = editor_->create_compilation_unit();

  const LIEF::lief_version_t& version = LIEF::extended_version();

  unit_->set_producer(
    fmt::format("BinaryNinja ABI {} with LIEF: {}.{}.{}.{}",
                BN_CURRENT_CORE_ABI_VERSION, version.major, version.minor,
                version.patch, version.id));

  auto type_engine = TypeEngine::create(*unit_, *bv_);
  auto func_engine = FunctionEngine::create(*type_engine, *unit_, *bv_);
  auto var_engine = VarEngine::create(*type_engine, *unit_, *bv_);

  for (bn::Function* func : bv_->GetAnalysisFunctionList()) {
    func_engine->add_function(*func);
  }

  for (const auto& [addr, var] : bv_->GetDataVariables()) {
    var_engine->add_variable(var);
  }

  return unit_.get();
}

std::string DwarfExport::save(const std::string& filename) {
  BN_DEBUG("Exporting DWARF Info from: {}", bv_->GetFile()->GetFilename());
  dw::CompilationUnit* unit = create();

  if (unit == nullptr) {
    return "";
  }

  editor_->write(filename);

  BN_INFO("Debug Information saved in {}", filename);
  return filename;
}

std::string DwarfExport::save() {
  std::string filename = bv_->GetFile()->GetFilename();
  if (size_t pos = filename.find(".bndb"); pos != std::string::npos) {
    filename = filename.substr(0, pos);
  }

  filename += ".debug_info";

  BN_DEBUG("Filename: {}", filename);
  return save(filename);
}
}
