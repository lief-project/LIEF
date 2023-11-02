/* Copyright 2017 - 2023 R. Thomas
 * Copyright 2017 - 2023 Quarkslab
 * Copyright 2017 - 2021, NVIDIA CORPORATION. All rights reserved
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
#ifndef LIEF_ELF_BUIDLER_H
#define LIEF_ELF_BUIDLER_H

#include <functional>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "LIEF/errors.hpp"

#include "LIEF/visibility.h"
#include "LIEF/iostream.hpp"
#include "LIEF/ELF/enums.hpp"

namespace LIEF {
namespace ELF {
class Binary;
class Layout;
class Header;
class Note;
class DynamicEntryArray;
class DynamicEntry;
class Section;
class ExeLayout;
class ObjectFileLayout;
class Layout;
class Relocation;

//! Class which takes an ELF::Binary object and reconstructs a valid binary
//!
//! This interface assumes that the layout of input ELF binary is correct (i.e.
//! the binary can run).
class LIEF_API Builder {
  friend class ObjectFileLayout;
  friend class Layout;
  friend class ExeLayout;

  public:
  //! Configuration options to tweak the building process
  struct config_t {
    bool android_rela    = true;  /// Rebuild DT_ANDROID_REL[A]
    bool dt_hash         = true;  /// Rebuild DT_HASH
    bool dyn_str         = true;  /// Rebuild DT_STRTAB
    bool dynamic_section = true;  /// Rebuild PT_DYNAMIC segment
    bool fini_array      = true;  /// Rebuild DT_FINI_ARRAY
    bool gnu_hash        = true;  /// Rebuild DT_GNU_HASH
    bool init_array      = true;  /// Rebuild DT_INIT_ARRAY
    bool interpreter     = true;  /// Rebuild PT_INTERPRETER
    bool jmprel          = true;  /// Rebuild DT_JMPREL
    bool notes           = false; /// Disable note building since it can break the default layout
    bool preinit_array   = true;  /// Rebuild DT_PREINIT_ARRAY
    bool rela            = true;  /// Rebuild DT_REL[A]
    bool relr            = true;  /// Rebuild DT_RELR
    bool static_symtab   = true;  /// Rebuild `.symtab`
    bool sym_verdef      = true;  /// Rebuild DT_VERDEF
    bool sym_verneed     = true;  /// Rebuild DT_VERNEED
    bool sym_versym      = true;  /// Rebuild DT_VERSYM
    bool symtab          = true;  /// Rebuild DT_SYMTAB

    bool force_relocate  = false; /// Force to relocating all the ELF structures that are supported by LIEF (mostly for testing)
  };

  Builder(Binary& binary);

  Builder() = delete;
  ~Builder();

  //! Perform the build of the provided ELF binary
  void build();

  //! Tweak the ELF builder with the provided config parameter
  Builder& set_config(config_t conf) {
    config_ = std::move(conf);
    return *this;
  }

  config_t& config() {
    return config_;
  }

  //! Return the built ELF binary as a byte vector
  const std::vector<uint8_t>& get_build();

  //! Write the built ELF binary in the ``filename`` given in parameter
  void write(const std::string& filename) const;

  //! Write the built ELF binary in the stream ``os`` given in parameter
  void write(std::ostream& os) const;

  protected:
  template<typename ELF_T>
  ok_error_t build();

  template<typename ELF_T>
  ok_error_t build_relocatable();

  template<typename ELF_T>
  ok_error_t build_exe_lib();

  template<typename ELF_T>
  ok_error_t build(const Header& header);

  template<typename ELF_T>
  ok_error_t build_sections();

  template<typename ELF_T>
  ok_error_t build_segments();

  template<typename ELF_T>
  ok_error_t build_static_symbols();

  template<typename ELF_T>
  ok_error_t build_dynamic_section();

  template<typename ELF_T>
  ok_error_t build_dynamic_symbols();

  template<typename ELF_T>
  ok_error_t build_obj_symbols();

  //! @see https://github.com/llvm/llvm-project/blob/llvmorg-17.0.3/lld/ELF/SyntheticSections.cpp#L1747
  template<typename ELF_T, typename Binary_T>
  static result<uint64_t> build_android_relocations(Binary_T *binary);

  //! @see https://groups.google.com/forum/#!topic/generic-abi/bX460iggiKg
  template<typename ELF_T, typename Binary_T>
  static result<uint64_t> build_relrdyn_relocations(Binary_T *binary);

  template<typename ELF_T>
  ok_error_t build_dynamic_relocations();

  template<typename ELF_T>
  ok_error_t build_pltgot_relocations();

  template<typename ELF_T>
  ok_error_t build_section_relocations();

  uint32_t sort_dynamic_symbols();

  template<typename ELF_T>
  ok_error_t build_hash_table();

  template<typename ELF_T>
  ok_error_t build_symbol_hash();

  ok_error_t build_empty_symbol_gnuhash();

  template<typename ELF_T>
  ok_error_t build_symbol_requirement();

  template<typename ELF_T>
  ok_error_t build_symbol_definition();

  template<typename ELF_T>
  ok_error_t build_symbol_version();

  template<typename ELF_T>
  ok_error_t build_interpreter();

  template<typename ELF_T>
  ok_error_t build_notes();

  ok_error_t build(const Note& note, std::set<Section*>& sections);

  template<typename ELF_T>
  ok_error_t build_overlay();

  bool should_swap() const;
  static bool should_swap(const Binary *binary);

  template<class ELF_T>
  ok_error_t process_object_relocations();

  config_t config_;
  mutable vector_iostream ios_;
  Binary* binary_{nullptr};
  std::unique_ptr<Layout> layout_;

};

} // namespace ELF
} // namespace LIEF




#endif
