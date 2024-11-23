/* Copyright 2022 - 2024 R. Thomas
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
#include "LIEF/DyldSharedCache/DyldSharedCache.hpp"
#include "LIEF/rust/DyldSharedCache/Dylib.hpp"
#include "LIEF/rust/DyldSharedCache/MappingInfo.hpp"
#include "LIEF/rust/DyldSharedCache/SubCache.hpp"

#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/helpers.hpp"
#include "LIEF/rust/Iterator.hpp"

class dsc_DyldSharedCache : private Mirror<LIEF::dsc::DyldSharedCache> {
  public:
  using lief_t = LIEF::dsc::DyldSharedCache;
  using Mirror::Mirror;

  class it_libraries :
      public RandomRangeIterator<dsc_Dylib, LIEF::dsc::Dylib::Iterator>
  {
    public:
    it_libraries(const dsc_DyldSharedCache::lief_t& src)
      : RandomRangeIterator(src.libraries()) { }
    auto next() { return RandomRangeIterator::next(); }
    auto size() const { return RandomRangeIterator::size(); }
  };

  class it_mapping_info :
      public RandomRangeIterator<dsc_MappingInfo, LIEF::dsc::MappingInfo::Iterator>
  {
    public:
    it_mapping_info(const dsc_DyldSharedCache::lief_t& src)
      : RandomRangeIterator(src.mapping_info()) { }
    auto next() { return RandomRangeIterator::next(); }
    auto size() const { return RandomRangeIterator::size(); }
  };

  class it_subcaches :
      public RandomRangeIterator<dsc_SubCache, LIEF::dsc::SubCache::Iterator>
  {
    public:
    it_subcaches(const dsc_DyldSharedCache::lief_t& src)
      : RandomRangeIterator(src.subcaches()) { }
    auto next() { return RandomRangeIterator::next(); }
    auto size() const { return RandomRangeIterator::size(); }
  };

  class it_instructions :
      public ForwardIterator<asm_Instruction, LIEF::assembly::Instruction::Iterator>
  {
    public:
    it_instructions(const dsc_DyldSharedCache::lief_t& src, uint64_t addr)
      : ForwardIterator(src.disassemble(addr)) { }
    auto next() { return ForwardIterator::next(); }
  };

  static auto from_path(std::string file, std::string arch) { // NOLINT(performance-unnecessary-value-param)
    return std::make_unique<dsc_DyldSharedCache>(LIEF::dsc::DyldSharedCache::from_path(file, arch));
  }

  static auto from_files(const char* ptr, size_t size) { // NOLINT(performance-unnecessary-value-param)
    const auto* files = (const char**)ptr;
    std::vector<std::string> files_vec;
    files_vec.reserve(size);
    for (size_t i = 0; i < size; ++i) {
      files_vec.push_back(files[i]);
    }
    return std::make_unique<dsc_DyldSharedCache>(LIEF::dsc::DyldSharedCache::from_files(files_vec));
  }

  auto libraries() const { return std::make_unique<it_libraries>(get()); }
  auto mapping_info() const { return std::make_unique<it_mapping_info>(get()); }
  auto subcaches() const { return std::make_unique<it_subcaches>(get()); }

  auto filename() const { return get().filename(); }
  auto version() const { return to_int(get().version()); }
  auto filepath() const { return get().filepath(); }
  auto load_address() const { return get().load_address(); }

  auto arch_name() const { return get().arch_name(); }
  auto platform() const { return to_int(get().platform()); }
  auto arch() const { return to_int(get().arch()); }
  auto has_subcaches() const { return get().has_subcaches(); }

  auto find_lib_from_va(uint64_t va) const {
    return details::try_unique<dsc_Dylib>(get().find_lib_from_va(va));
  }

  auto find_lib_from_path(std::string path) const {
    return details::try_unique<dsc_Dylib>(get().find_lib_from_path(path));
  }

  auto find_lib_from_name(std::string name) const {
    return details::try_unique<dsc_Dylib>(get().find_lib_from_name(name));
  }

  auto enable_caching(std::string dir) const { get().enable_caching(dir); }
  auto flush_cache() const { get().flush_cache(); }

  auto disassemble(uint64_t addr) const {
    return std::make_unique<it_instructions>(get(), addr);
  }

  auto cache_for_address(uint64_t addr) const {
    return details::try_unique<dsc_DyldSharedCache>(get().cache_for_address(addr));
  }

  auto main_cache() const {
    return details::try_unique<dsc_DyldSharedCache>(get().main_cache());
  }

  auto find_subcache(std::string filename) const {
    return details::try_unique<dsc_DyldSharedCache>(get().find_subcache(filename));
  }

  uint64_t va_to_offset(uint64_t va, uint32_t& err) const {
    return details::make_error(get().va_to_offset(va), err);
  }

  auto get_content_from_va(uint64_t va, uint64_t size) const {
    return get().get_content_from_va(va, size);
  }

};
