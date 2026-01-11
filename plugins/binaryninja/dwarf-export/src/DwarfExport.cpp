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
#include <binaryninja/binaryninjaapi.h>
#include <binaryninja/binaryninjacore.h>

#include "binaryninja/lief_utils.hpp"

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

#include "binaryninja/dwarf-export/log.hpp"
#include "binaryninja/dwarf-export/DwarfExport.hpp"
#include "binaryninja/dwarf-export/FunctionEngine.hpp"
#include "binaryninja/dwarf-export/VarEngine.hpp"
#include "binaryninja/dwarf-export/TypeEngine.hpp"
#include "log.hpp"

namespace bn = BinaryNinja;

namespace dw = LIEF::dwarf::editor;

using FORMAT = LIEF::dwarf::Editor::FORMAT;
using ARCH = LIEF::dwarf::Editor::ARCH;

namespace dwarf_plugin {

inline bool startwith(const std::string& s, const char* prefix) {
  return s.rfind(prefix, 0) == 0;
}

DwarfExport::~DwarfExport() = default;

DwarfExport::DwarfExport(BinaryNinja::BinaryView& bv) :
  bv_{&bv}
{}

std::pair<FORMAT, ARCH> get_fmt_arch(const bn::BinaryView& bv) {
  FORMAT fmt = FORMAT::ELF;
  ARCH arch = ARCH::X64;

  if (bn::Ref<bn::Platform> platform = bv.GetDefaultPlatform()) {
    const std::string& name = platform->GetName();
    if (startwith(name, "linux-") || startwith(name, "freebsd-")) {
      fmt = FORMAT::ELF;
    }
    else if (startwith(name, "mac-")) {
      fmt = FORMAT::MACHO;
    }
    else if (startwith(name, "windows-") || startwith(name, "efi-")) {
      fmt = FORMAT::PE;
    }
    else {
      BN_WARN("Platform '{}' is not supported", name);
    }
  }


  if (bn::Ref<bn::Architecture> target_arch = bv.GetDefaultArchitecture()) {
    const std::string& name = target_arch->GetName();
    if (name == "aarch64") {
      arch = ARCH::AARCH64;
    }
    else if (name == "x86") {
      arch = ARCH::X86;
    }
    else if (name == "x86_64") {
      arch = ARCH::X64;
    }
    else if (name == "armv7") {
      arch = ARCH::ARM;
    }
    else {
      BN_WARN("Architecture '{}' is not supported", name);
    }
  }

  return {fmt, arch};
}

dw::CompilationUnit* DwarfExport::create() {
  const auto& [fmt, arch] = get_fmt_arch(*bv_);

  editor_ = LIEF::dwarf::Editor::create(fmt, arch);
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
