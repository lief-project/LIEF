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
#ifndef LIEF_MACHO_BUIDLER_H_
#define LIEF_MACHO_BUIDLER_H_

#include <algorithm>
#include <vector>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

#include "LIEF/errors.hpp"
#include "LIEF/visibility.h"
#include "LIEF/exception.hpp"
#include "LIEF/iostream.hpp"

struct Profiler;

namespace LIEF {
namespace MachO {

class Binary;
class BuildVersion;
class CodeSignature;
class CodeSignatureDir;
class DataInCode;
class DyldChainedFixups;
class DyldEnvironment;
class DyldExportsTrie;
class DyldInfo;
class DylibCommand;
class DylinkerCommand;
class DynamicSymbolCommand;
class FatBinary;
class FunctionStarts;
class LinkerOptHint;
class MainCommand;
class SegmentSplitInfo;
class SourceVersion;
class SubFramework;
class SymbolCommand;
class ThreadCommand;
class TwoLevelHints;
class VersionMin;

//! Class used to rebuild a Mach-O file
class LIEF_API Builder {
  public:
  friend struct ::Profiler;

  //! Options to tweak the building process
  struct config_t {
    bool linkedit = true;
  };

  static ok_error_t write(Binary& binary, const std::string& filename);
  static ok_error_t write(Binary& binary, const std::string& filename, config_t config);

  static ok_error_t write(Binary& binary, std::vector<uint8_t>& out);
  static ok_error_t write(Binary& binary, std::vector<uint8_t>& out, config_t config);

  static ok_error_t write(Binary& binary, std::ostream& out);
  static ok_error_t write(Binary& binary, std::ostream& out, config_t config);

  static ok_error_t write(FatBinary& fat, const std::string& filename);
  static ok_error_t write(FatBinary& fat, const std::string& filename, config_t config);

  static ok_error_t write(FatBinary& fat, std::vector<uint8_t>& out);
  static ok_error_t write(FatBinary& fat, std::vector<uint8_t>& out, config_t config);

  static ok_error_t write(FatBinary& fat, std::ostream& out);
  static ok_error_t write(FatBinary& fat, std::ostream& out, config_t config);
  
  ~Builder();
  private:
  ok_error_t build();

  const std::vector<uint8_t>& get_build();
  ok_error_t write(const std::string& filename) const;
  ok_error_t write(std::ostream& os) const;
  
  Builder(Binary& binary, config_t config);
  Builder(std::vector<Binary*> binaries, config_t config);

  Builder() = delete;

  static std::vector<uint8_t> build_raw(Binary& binary, config_t config);
  static std::vector<uint8_t> build_raw(FatBinary& binary, config_t config);

  template<typename T>
  ok_error_t build();

  ok_error_t build_fat();
  ok_error_t build_fat_header();
  ok_error_t build_header();
  ok_error_t build_load_commands();

  template<typename T>
  ok_error_t build_linkedit();

  template<typename T>
  ok_error_t build(DylibCommand& library);

  template<typename T>
  ok_error_t build(DylinkerCommand& linker);

  template<class T>
  ok_error_t build(VersionMin& version_min);

  template<class T>
  ok_error_t build(SourceVersion& source_version);

  template<class T>
  ok_error_t build(FunctionStarts& function_starts);

  template<class T>
  ok_error_t build(MainCommand& main_cmd);

  template<class T>
  ok_error_t build(DyldInfo& dyld_info);

  template<class T>
  ok_error_t build(SymbolCommand& symbol_command);

  template<class T>
  ok_error_t build(DynamicSymbolCommand& symbol_command);

  template<class T>
  ok_error_t build(DataInCode& datacode);

  template<class T>
  ok_error_t build(CodeSignature& code_signature);

  template<class T>
  ok_error_t build(SegmentSplitInfo& ssi);

  template<class T>
  ok_error_t build(SubFramework& sf);

  template<class T>
  ok_error_t build(DyldEnvironment& de);

  template<class T>
  ok_error_t build(ThreadCommand& tc);

  template<class T>
  ok_error_t build(DyldChainedFixups& fixups);

  template<class T>
  ok_error_t build(DyldExportsTrie& exports);

  template<class T>
  ok_error_t build(TwoLevelHints& two);

  template<class T>
  ok_error_t build(LinkerOptHint& opt);

  template<class T>
  ok_error_t build(CodeSignatureDir& sig);

  template <typename T>
  ok_error_t build_segments();

  template<class T>
  ok_error_t build(BuildVersion& bv);

  template <typename T>
  ok_error_t build_symbols();

  ok_error_t build_uuid();

  template <typename T>
  ok_error_t update_fixups(DyldChainedFixups& fixups);



  std::vector<Binary*> binaries_;
  Binary* binary_ = nullptr;
  mutable vector_iostream raw_;
  uint64_t linkedit_offset_ = 0;
  mutable vector_iostream linkedit_;
  config_t config_;
};

} // namespace MachO
} // namespace LIEF
#endif
