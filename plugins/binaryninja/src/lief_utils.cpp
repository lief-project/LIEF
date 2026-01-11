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
#include <sstream>
#include <fstream>
#include <filesystem>

#include "binaryninja/lief_utils.hpp"
#include "binaryninja/log_core.hpp"

#include <binaryninja/binaryninjaapi.h>
#include <binaryninja/binaryninjacore.h>

#include <LIEF/MachO/utils.hpp>
#include <LIEF/MachO/Parser.hpp>
#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/FatBinary.hpp>
#include <LIEF/MachO/Header.hpp>
#include <LIEF/ELF/utils.hpp>
#include <LIEF/PE/utils.hpp>
#include <LIEF/COFF/utils.hpp>
#include <LIEF/DyldSharedCache/utils.hpp>

namespace binaryninja {

namespace bn = BinaryNinja;

namespace fs = std::filesystem;

FileFormat get_file_format(BinaryNinja::BinaryView& bv) {
  std::string original_file = bv.GetFile()->GetOriginalFilename();

  if (LIEF::MachO::is_macho(original_file)) {
    return FileFormat::MachO;
  }

  if (LIEF::PE::is_pe(original_file)) {
    return FileFormat::PE;
  }

  if (LIEF::ELF::is_elf(original_file)) {
    return FileFormat::ELF;
  }

  if (LIEF::COFF::is_coff(original_file)) {
    return FileFormat::COFF;
  }

  if (LIEF::dsc::is_shared_cache(original_file)) {
    return FileFormat::DSC;
  }

  return FileFormat::Unknown;
}

std::unique_ptr<LIEF::Binary> get_bin(BinaryNinja::BinaryView& bv) {
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


std::string to_string(const BinaryNinja::QualifiedName& name) {
  if (name.IsEmpty()) {
    return "";
  }

  if (name.size() == 1) {
    return name.GetString();
  }

  return fmt::to_string(fmt::join(name, name.GetJoinString()));
}

std::string to_string(BinaryNinja::BinaryView& bv) {
  auto settings = bn::DisassemblySettings::GetDefaultLinearSettings();

  auto disassembly = bn::LinearViewObject::CreateDisassembly(&bv, settings);
  bn::LinearViewCursor cursor(BNCreateLinearViewCursor(disassembly->GetObject()));
  cursor.SeekToBegin();
  std::ostringstream oss;
  while (cursor.IsValid()) {
    for (const bn::LinearDisassemblyLine& line : cursor.GetLines()) {
      oss << to_string(line) << '\n';
    }
    cursor.Next();
  }
  return oss.str();
}

std::string to_string(const BinaryNinja::LinearDisassemblyLine& line) {
  std::ostringstream oss;
  for (const bn::InstructionTextToken& token : line.contents.tokens) {
    oss << token.text;
  }
  return oss.str();
}

void linear_export(BinaryNinja::BinaryView& bv, const std::string& file) {
  std::ofstream ofs(file);
  if (ofs) {
    ofs << to_string(bv);
  }
}

std::optional<std::string> find_typelib(const std::string& name) {
  std::vector<std::string> candidates;
  for (const auto& path : {bn::GetUserDirectory(), bn::GetInstallDirectory()}) {
    if (fs::path install_dir = path; fs::is_directory(install_dir)) {
      if (auto candidate = install_dir / name; fs::exists(candidate)) {
        return fs::absolute(candidate).string();
      } else {
        candidates.push_back(candidate.string());
      }

      if (auto candidate = install_dir / "typelib" / name; fs::exists(candidate)) {
        return fs::absolute(candidate).string();
      } else {
        candidates.push_back(candidate.string());
      }
    }
  }
  BN_WARN("Could not find {} in the following locations:\n{}", name,
          fmt::join(candidates, "\n-"));
  return std::nullopt;
}

}
