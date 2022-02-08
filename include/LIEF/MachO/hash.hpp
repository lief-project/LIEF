/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#ifndef LIEF_MACHO_HASH_H_
#define LIEF_MACHO_HASH_H_

#include "LIEF/visibility.h"
#include "LIEF/hash.hpp"

namespace LIEF {
namespace MachO {

class Binary;
class Header;
class LoadCommand;
class UUIDCommand;
class SymbolCommand;
class SegmentCommand;
class Section;
class MainCommand;
class DynamicSymbolCommand;
class DylinkerCommand;
class DylibCommand;
class ThreadCommand;
class RPathCommand;
class Symbol;
class Relocation;
class RelocationObject;
class RelocationDyld;
class BindingInfo;
class ExportInfo;
class FunctionStarts;
class CodeSignature;
class DataInCode;
class DataCodeEntry;
class VersionMin;
class SourceVersion;
class SegmentSplitInfo;
class SubFramework;
class DyldEnvironment;
class EncryptionInfo;
class BuildVersion;
class BuildToolVersion;
class FilesetCommand;

//! Class which implements a visitor to compute
//! a **deterministic** hash for LIEF MachO objects
class LIEF_API Hash : public LIEF::Hash {
  public:
  static size_t hash(const Object& obj);

  public:
  using LIEF::Hash::Hash;
  using LIEF::Hash::visit;

  public:
  void visit(const Binary& binary)                        override;
  void visit(const Header& header)                        override;
  void visit(const LoadCommand& cmd)                      override;
  void visit(const UUIDCommand& uuid)                     override;
  void visit(const SymbolCommand& symbol)                 override;
  void visit(const SegmentCommand& segment)               override;
  void visit(const Section& section)                      override;
  void visit(const MainCommand& maincmd)                  override;
  void visit(const DynamicSymbolCommand& dynamic_symbol)  override;
  void visit(const DylinkerCommand& dylinker)             override;
  void visit(const DylibCommand& dylib)                   override;
  void visit(const ThreadCommand& threadcmd)              override;
  void visit(const RPathCommand& rpath)                   override;
  void visit(const Symbol& symbol)                        override;
  void visit(const Relocation& relocation)                override;
  void visit(const RelocationObject& robject)             override;
  void visit(const RelocationDyld& rdyld)                 override;
  void visit(const BindingInfo& binding)                  override;
  void visit(const ExportInfo& einfo)                     override;
  void visit(const FunctionStarts& fs)                    override;
  void visit(const CodeSignature& cs)                     override;
  void visit(const DataInCode& dic)                       override;
  void visit(const DataCodeEntry& dce)                    override;
  void visit(const VersionMin& vmin)                      override;
  void visit(const SourceVersion& sv)                     override;
  void visit(const SegmentSplitInfo& ssi)                 override;
  void visit(const SubFramework& sf)                      override;
  void visit(const DyldEnvironment& sf)                   override;
  void visit(const EncryptionInfo& e)                     override;
  void visit(const BuildVersion& e)                       override;
  void visit(const BuildToolVersion& e)                   override;
  void visit(const FilesetCommand& e)                     override;

  ~Hash() override;
};

}
}

#endif
