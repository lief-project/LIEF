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
class FatBinary;
class DylibCommand;
class DylinkerCommand;
class VersionMin;
class SourceVersion;
class FunctionStarts;
class MainCommand;
class DyldInfo;
class SymbolCommand;
class DynamicSymbolCommand;
class DataInCode;
class CodeSignature;
class SegmentSplitInfo;
class SubFramework;
class DyldEnvironment;
class ThreadCommand;
class BuildVersion;

//! Class that is used to rebuilt a Mach-O file
class LIEF_API Builder {
  public:
  friend struct ::Profiler;

  static void write(Binary& binary, const std::string& filename);
  static void write(FatBinary& fatbinary, const std::string& filename);

  public:
  Builder(Binary& binary);
  Builder(std::vector<Binary*> binaries);
  Builder(FatBinary& fat);

  Builder() = delete;
  ~Builder();

  void build();

  const std::vector<uint8_t>& get_build();
  void write(const std::string& filename) const;

  private:
  template<typename T>
  ok_error_t build();

  template<typename T, typename HANDLER>
  std::vector<std::string> optimize(const HANDLER& e,
                                    std::function<std::string(const typename HANDLER::value_type)> getter,
                                    std::unordered_map<std::string, size_t> *of_map_p=nullptr);

  ok_error_t build_fat();
  ok_error_t build_fat_header();
  ok_error_t build_header();
  ok_error_t build_load_commands();

  template<typename T>
  ok_error_t build(DylibCommand* library);

  template<typename T>
  ok_error_t build(DylinkerCommand* linker);

  template<class T>
  ok_error_t build(VersionMin* version_min);

  template<class T>
  ok_error_t build(SourceVersion* source_version);

  template<class T>
  ok_error_t build(FunctionStarts* function_starts);

  template<class T>
  ok_error_t build(MainCommand* main_cmd);

  template<class T>
  ok_error_t build(DyldInfo* dyld_info);

  template<class T>
  ok_error_t build(SymbolCommand* symbol_command);

  template<class T>
  ok_error_t build(DynamicSymbolCommand* symbol_command);

  template<class T>
  ok_error_t build(DataInCode* datacode);

  template<class T>
  ok_error_t build(CodeSignature* code_signature);

  template<class T>
  ok_error_t build(SegmentSplitInfo* ssi);

  template<class T>
  ok_error_t build(SubFramework* sf);

  template<class T>
  ok_error_t build(DyldEnvironment* de);

  template<class T>
  ok_error_t build(ThreadCommand* tc);

  template <typename T>
  ok_error_t build_segments();

  template<class T>
  ok_error_t build(BuildVersion* bv);

  template <typename T>
  ok_error_t build_symbols();

  ok_error_t build_uuid();

  std::vector<Binary*> binaries_;
  Binary* binary_ = nullptr;
  mutable vector_iostream raw_;
};

} // namespace MachO
} // namespace LIEF
#endif
