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
#ifndef LIEF_OAT_HEADER_H_
#define LIEF_OAT_HEADER_H_
#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "LIEF/OAT/enums.hpp"
#include "LIEF/OAT/type_traits.hpp"
#include "LIEF/Object.hpp"
#include "LIEF/iterators.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace OAT {
class Parser;

class LIEF_API Header : public Object {
  friend class Parser;

 public:
  using magic_t = std::array<uint8_t, 4>;  // oat\n
  using key_values_t = std::map<HEADER_KEYS, std::string>;
  using it_key_values_t = ref_iterator<
      std::vector<std::pair<HEADER_KEYS, std::reference_wrapper<std::string>>>>;
  using it_const_key_values_t =
      const_ref_iterator<std::vector<std::pair<HEADER_KEYS, std::string>>>;

  //! @brief Iterator type over
  using keys_t = std::vector<HEADER_KEYS>;
  using values_t = std::vector<std::string>;

 public:
  //! Return the string value associated with the given key
  static std::string key_to_string(HEADER_KEYS key);

 public:
  Header();
  Header(const Header&);
  Header& operator=(const Header&);

  template <class T>
  LIEF_LOCAL Header(const T* header);

  //! Magic value: ``oat``
  Header::magic_t magic() const;

  //! OAT version
  oat_version_t version() const;

  uint32_t checksum() const;

  INSTRUCTION_SETS instruction_set() const;
  // TODO instruction_set_features_bitmap_() const;

  uint32_t nb_dex_files() const;

  // Since OAT 131
  uint32_t oat_dex_files_offset() const;

  uint32_t executable_offset() const;
  uint32_t i2i_bridge_offset() const;
  uint32_t i2c_code_bridge_offset() const;
  uint32_t jni_dlsym_lookup_offset() const;

  uint32_t quick_generic_jni_trampoline_offset() const;
  uint32_t quick_imt_conflict_trampoline_offset() const;
  uint32_t quick_resolution_trampoline_offset() const;
  uint32_t quick_to_interpreter_bridge_offset() const;

  int32_t image_patch_delta() const;

  uint32_t image_file_location_oat_checksum() const;
  uint32_t image_file_location_oat_data_begin() const;

  uint32_t key_value_size() const;

  it_key_values_t key_values();
  it_const_key_values_t key_values() const;

  keys_t keys() const;
  values_t values() const;

  const std::string* get(HEADER_KEYS key) const;
  std::string* get(HEADER_KEYS key);

  Header& set(HEADER_KEYS key, const std::string& value);

  const std::string* operator[](HEADER_KEYS key) const;
  std::string* operator[](HEADER_KEYS key);

  void magic(const magic_t& magic);

  void accept(Visitor& visitor) const override;

  bool operator==(const Header& rhs) const;
  bool operator!=(const Header& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Header& hdr);

 private:
  magic_t magic_;
  oat_version_t version_ = 0;
  uint32_t checksum_ = 0;
  INSTRUCTION_SETS instruction_set_ = INSTRUCTION_SETS::INST_SET_NONE;
  uint32_t instruction_set_features_bitmap_ = 0;
  uint32_t dex_file_count_ = 0;
  uint32_t oat_dex_files_offset_ = 0;  // Since OAT 131 / Android 8.1.0
  uint32_t executable_offset_ = 0;
  uint32_t i2i_bridge_offset_ = 0;
  uint32_t i2c_code_bridge_offset_ = 0;
  uint32_t jni_dlsym_lookup_offset_ = 0;

  uint32_t quick_generic_jni_trampoline_offset_ = 0;
  uint32_t quick_imt_conflict_trampoline_offset_ = 0;
  uint32_t quick_resolution_trampoline_offset_ = 0;
  uint32_t quick_to_interpreter_bridge_offset_ = 0;

  int32_t image_patch_delta_ = 0;

  uint32_t image_file_location_oat_checksum_ = 0;
  uint32_t image_file_location_oat_data_begin_ = 0;

  uint32_t key_value_store_size_ = 0;

  key_values_t dex2oat_context_;
};

}  // namespace OAT
}  // namespace LIEF

#endif
