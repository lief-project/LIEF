/* Copyright 2021 - 2022 R. Thomas
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
#ifndef LIEF_ELF_LAYOUT_H_
#define LIEF_ELF_LAYOUT_H_
#include <unordered_map>
#include <string>
#include <vector>
namespace LIEF {
namespace ELF {
class Section;
class Binary;
class Layout {
  public:
  Layout(Binary& bin);

  inline virtual const std::unordered_map<std::string, size_t>& shstr_map() const {
    return shstr_name_map_;
  }

  inline virtual const std::unordered_map<std::string, size_t>& strtab_map() const {
    return strtab_name_map_;
  }

  inline virtual const std::vector<uint8_t>& raw_shstr() const {
    return raw_shstrtab_;
  }

  inline virtual const std::vector<uint8_t>& raw_strtab() const {
    return raw_strtab_;
  }

  inline void set_strtab_section(Section& section) {
    strtab_section_ = &section;
  }

  inline void set_dyn_sym_idx(int32_t val) {
    new_symndx_ = val;
  }

  bool is_strtab_shared_shstrtab() const;
  size_t section_strtab_size();
  size_t section_shstr_size();

  virtual ~Layout();
  Layout() = delete;

  protected:
  Binary* binary_ = nullptr;

  std::unordered_map<std::string, size_t> shstr_name_map_;
  std::unordered_map<std::string, size_t> strtab_name_map_;

  std::vector<uint8_t> raw_shstrtab_;
  std::vector<uint8_t> raw_strtab_;

  Section* strtab_section_ = nullptr;
  int32_t new_symndx_ = -1;
};
}
}
#endif
