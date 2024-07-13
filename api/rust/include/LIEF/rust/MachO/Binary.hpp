/* Copyright 2024 R. Thomas
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

#pragma once
#include <memory>
#include <LIEF/MachO.hpp>

#include "LIEF/rust/MachO/LoadCommand.hpp"
#include "LIEF/rust/MachO/Header.hpp"
#include "LIEF/rust/MachO/Symbol.hpp"
#include "LIEF/rust/MachO/Dylib.hpp"
#include "LIEF/rust/MachO/SegmentCommand.hpp"
#include "LIEF/rust/MachO/Relocation.hpp"
#include "LIEF/rust/MachO/DyldInfo.hpp"
#include "LIEF/rust/MachO/UUIDCommand.hpp"
#include "LIEF/rust/MachO/Main.hpp"
#include "LIEF/rust/MachO/Dylinker.hpp"
#include "LIEF/rust/MachO/SourceVersion.hpp"
#include "LIEF/rust/MachO/ThreadCommand.hpp"
#include "LIEF/rust/MachO/FunctionStarts.hpp"
#include "LIEF/rust/MachO/RPathCommand.hpp"
#include "LIEF/rust/MachO/SymbolCommand.hpp"
#include "LIEF/rust/MachO/DynamicSymbolCommand.hpp"
#include "LIEF/rust/MachO/CodeSignature.hpp"
#include "LIEF/rust/MachO/CodeSignatureDir.hpp"
#include "LIEF/rust/MachO/DataInCode.hpp"
#include "LIEF/rust/MachO/SegmentSplitInfo.hpp"
#include "LIEF/rust/MachO/EncryptionInfo.hpp"
#include "LIEF/rust/MachO/SubFramework.hpp"
#include "LIEF/rust/MachO/DyldEnvironment.hpp"
#include "LIEF/rust/MachO/BuildVersion.hpp"
#include "LIEF/rust/MachO/DyldChainedFixups.hpp"
#include "LIEF/rust/MachO/DyldExportsTrie.hpp"
#include "LIEF/rust/MachO/VersionMin.hpp"
#include "LIEF/rust/MachO/TwoLevelHints.hpp"
#include "LIEF/rust/MachO/LinkerOptHint.hpp"

#include "LIEF/rust/Abstract/Binary.hpp"

#include "LIEF/rust/ObjC/Metadata.hpp"

class MachO_Binary : public AbstractBinary {
  public:
  using lief_t = LIEF::MachO::Binary;

  class it_commands :
      public Iterator<MachO_Command, LIEF::MachO::Binary::it_const_commands>
  {
    public:
    it_commands(const MachO_Binary::lief_t& src)
      : Iterator(std::move(src.commands())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_symbols :
      public Iterator<MachO_Symbol, LIEF::MachO::Binary::it_const_symbols>
  {
    public:
    it_symbols(const MachO_Binary::lief_t& src)
      : Iterator(std::move(src.symbols())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_sections :
      public Iterator<MachO_Section, LIEF::MachO::Binary::it_const_sections>
  {
    public:
    it_sections(const MachO_Binary::lief_t& src)
      : Iterator(std::move(src.sections())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_segments :
      public Iterator<MachO_SegmentCommand, LIEF::MachO::Binary::it_const_segments>
  {
    public:
    it_segments(const MachO_Binary::lief_t& src)
      : Iterator(std::move(src.segments())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_libraries :
      public Iterator<MachO_Dylib, LIEF::MachO::Binary::it_const_libraries>
  {
    public:
    it_libraries(const MachO_Binary::lief_t& src)
      : Iterator(std::move(src.libraries())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  class it_relocations :
      public Iterator<MachO_Relocation, LIEF::MachO::Binary::it_const_relocations>
  {
    public:
    it_relocations(const MachO_Binary::lief_t& src)
      : Iterator(std::move(src.relocations())) { }
    auto next() { return Iterator::next(); }
    auto size() const { return Iterator::size(); }
  };

  MachO_Binary(const lief_t& bin) : AbstractBinary(bin) {}

  auto header() const {
    return std::make_unique<MachO_Header>(impl().header());
  }

  auto commands() const { return std::make_unique<it_commands>(impl()); }
  auto symbols() const { return std::make_unique<it_symbols>(impl()); }
  auto sections() const { return std::make_unique<it_sections>(impl()); }
  auto segments() const { return std::make_unique<it_segments>(impl()); }
  auto libraries() const { return std::make_unique<it_libraries>(impl()); }
  auto relocations() const { return std::make_unique<it_relocations>(impl()); }

  auto dyld_info() const {
    return details::try_unique<MachO_DyldInfo>(impl().dyld_info());
  }

  auto uuid() const {
    return details::try_unique<MachO_UUIDCommand>(impl().uuid());
  }

  auto main_command() const {
    return details::try_unique<MachO_Main>(impl().main_command());
  }

  auto dylinker() const {
    return details::try_unique<MachO_Dylinker>(impl().dylinker());
  }

  auto function_starts() const {
    return details::try_unique<MachO_FunctionStarts>(impl().function_starts());
  }

  auto source_version() const {
    return details::try_unique<MachO_SourceVersion>(impl().source_version());
  }

  auto thread_command() const {
    return details::try_unique<MachO_ThreadCommand>(impl().thread_command());
  }

  auto rpath() const {
    return details::try_unique<MachO_RPathCommand>(impl().rpath());
  }

  auto symbol_command() const {
    return details::try_unique<MachO_SymbolCommand>(impl().symbol_command());
  }

  auto dynamic_symbol_command() const {
    return details::try_unique<MachO_DynamicSymbolCommand>(impl().dynamic_symbol_command());
  }

  auto code_signature() const {
    return details::try_unique<MachO_CodeSignature>(impl().code_signature());
  }

  auto code_signature_dir() const {
    return details::try_unique<MachO_CodeSignatureDir>(impl().code_signature_dir());
  }

  auto data_in_code() const {
    return details::try_unique<MachO_DataInCode>(impl().data_in_code());
  }

  auto segment_split_info() const {
    return details::try_unique<MachO_SegmentSplitInfo>(impl().segment_split_info());
  }

  auto encryption_info() const {
    return details::try_unique<MachO_EncryptionInfo>(impl().encryption_info());
  }

  auto sub_framework() const {
    return details::try_unique<MachO_SubFramework>(impl().sub_framework());
  }

  auto dyld_environment() const {
    return details::try_unique<MachO_DyldEnvironment>(impl().dyld_environment());
  }

  auto build_version() const {
    return details::try_unique<MachO_BuildVersion>(impl().build_version());
  }

  auto dyld_chained_fixups() const {
    return details::try_unique<MachO_DyldChainedFixups>(impl().dyld_chained_fixups());
  }

  auto dyld_exports_trie() const {
    return details::try_unique<MachO_DyldExportsTrie>(impl().dyld_exports_trie());
  }

  auto two_level_hints() const {
    return details::try_unique<MachO_TwoLevelHints>(impl().two_level_hints());
  }

  auto linker_opt_hint() const {
    return details::try_unique<MachO_LinkerOptHint>(impl().linker_opt_hint());
  }

  auto version_min() const {
    return details::try_unique<MachO_VersionMin>(impl().version_min());
  }

  auto support_arm64_ptr_auth() const {
    return impl().support_arm64_ptr_auth();
  }

  auto objc_metadata() const {
    return details::try_unique<ObjC_Metadata>(impl().objc_metadata());
  }

  static bool is_exported(const MachO_Symbol& symbol) {
    return lief_t::is_exported(static_cast<const LIEF::MachO::Symbol&>(symbol.get()));
  }
  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
