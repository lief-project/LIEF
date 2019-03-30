/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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

#include "LIEF/visibility.h"
#include "LIEF/exception.hpp"
#include "LIEF/iostream.hpp"

#include "LIEF/MachO/Binary.hpp"
#include "LIEF/MachO/FatBinary.hpp"
#include "LIEF/MachO/EnumToString.hpp"

namespace LIEF {
namespace MachO {


class LIEF_API Builder {
  public:
  static void write(Binary *binary, const std::string& filename);
  static void write(FatBinary* fatbinary, const std::string& filename);

  public:
  Builder(Binary *binary);
  Builder(std::vector<Binary*> binaries);
  Builder(FatBinary* fat);

  Builder(void) = delete;
  ~Builder(void);

  std::vector<uint8_t> operator()(void);
  void build(void);

  const std::vector<uint8_t>& get_build(void);
  void write(const std::string& filename) const;

  private:
  template<typename T>
  void build(void);

  void build_fat(void);
  void build_fat_header(void);
  void build_header(void);
  void build_load_commands(void);

  template<typename T>
  void build(DylibCommand* library);

  template<typename T>
  void build(DylinkerCommand* linker);

  template<class T>
  void build(VersionMin* version_min);

  template<class T>
  void build(SourceVersion* source_version);

  template<class T>
  void build(FunctionStarts* function_starts);

  template<class T>
  void build(MainCommand* main_cmd);

  template<class T>
  void build(DyldInfo* dyld_info);

  template<class T>
  void build(SymbolCommand* symbol_command);

  template<class T>
  void build(DynamicSymbolCommand* symbol_command);

  template<class T>
  void build(DataInCode* datacode);

  template<class T>
  void build(CodeSignature* code_signature);

  template<class T>
  void build(SegmentSplitInfo* ssi);

  template<class T>
  void build(SubFramework* sf);

  template<class T>
  void build(DyldEnvironment* de);

  template<class T>
  void build(ThreadCommand* tc);

  template <typename T>
  void build_segments(void);

  template<class T>
  void build(BuildVersion* bv);

  void build_uuid(void);


  template <typename T>
  void build_symbols(void);

  std::vector<Binary*> binaries_;
  Binary*              binary_{nullptr};
  mutable vector_iostream raw_;
};

} // namespace MachO
} // namespace LIEF
#endif
