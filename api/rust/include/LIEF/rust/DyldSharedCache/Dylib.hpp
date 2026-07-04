/* Copyright 2022 - 2026 R. Thomas
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
#include "LIEF/DyldSharedCache/Dylib.hpp"
#include "LIEF/rust/Mirror.hpp"
#include "LIEF/rust/MachO/Binary.hpp"
#include "LIEF/rust/helpers.hpp"

class dsc_Dylib_extract_opt {
  public:
  bool pack = true;
  bool fix_branches = false;
  bool fix_memory = false;
  bool fix_relocations = false;
  bool fix_objc = false;

  bool create_dyld_chained_fixup_cmd = false;
  bool create_dyld_chained_fixup_cmd_set = false;
};

inline LIEF::dsc::Dylib::extract_opt_t
    from_rust(const dsc_Dylib_extract_opt& opt) {
  LIEF::dsc::Dylib::extract_opt_t out;

  out.pack = opt.pack;
  out.fix_branches = opt.fix_branches;
  out.fix_memory = opt.fix_memory;
  out.fix_relocations = opt.fix_relocations;
  out.fix_objc = opt.fix_objc;
  if (opt.create_dyld_chained_fixup_cmd_set) {
    out.create_dyld_chained_fixup_cmd = opt.create_dyld_chained_fixup_cmd;
  }
  return out;
}

class dsc_Dylib : private Mirror<LIEF::dsc::Dylib> {
  public:
  using lief_t = LIEF::dsc::Dylib;
  using Mirror::Mirror;

  auto path() const {
    return to_unique_string(get().path());
  }
  auto address() const {
    return get().address();
  }
  auto modtime() const {
    return get().modtime();
  }
  auto inode() const {
    return get().inode();
  }
  auto padding() const {
    return get().padding();
  }

  auto get_macho(const dsc_Dylib_extract_opt& opt) const {
    return details::try_unique<MachO_Binary>(get().get(from_rust(opt)));
  }
};
