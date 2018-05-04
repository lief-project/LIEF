
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
#ifndef LIEF_DEX_HEADER_H_
#define LIEF_DEX_HEADER_H_

#include "LIEF/DEX/type_traits.hpp"
#include "LIEF/DEX/Structures.hpp"

#include "LIEF/visibility.h"
#include "LIEF/Object.hpp"

namespace LIEF {
namespace DEX {
class Parser;

class LIEF_API Header : public Object {
  friend class Parser;

  public:
  using location_t = std::pair<uint32_t, uint32_t>;
  Header(void);
  Header(const Header&);
  Header& operator=(const Header&);

  template<class T>
  LIEF_LOCAL Header(const T* header);

  magic_t magic(void) const;
  uint32_t checksum(void) const;
  signature_t signature(void) const;

  uint32_t file_size(void) const;
  uint32_t header_size(void) const;
  uint32_t endian_tag(void) const;

  uint32_t map(void) const;

  location_t strings(void) const;
  location_t link(void) const;
  location_t types(void) const;
  location_t prototypes(void) const;
  location_t fields(void) const;
  location_t methods(void) const;
  location_t classes(void) const;
  location_t data(void) const;

  uint32_t nb_classes(void) const;

  uint32_t nb_methods(void) const;

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const Header& rhs) const;
  bool operator!=(const Header& rhs) const;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Header& hdr);

  virtual ~Header(void);

  private:

  magic_t magic_;
  uint32_t checksum_;
  signature_t signature_;
  uint32_t file_size_;

  uint32_t header_size_;
  uint32_t endian_tag_;

  uint32_t link_size_;
  uint32_t link_off_;

  uint32_t map_off_;

  uint32_t string_ids_size_;
  uint32_t string_ids_off_;

  uint32_t type_ids_size_;
  uint32_t type_ids_off_;

  uint32_t proto_ids_size_;
  uint32_t proto_ids_off_;

  uint32_t field_ids_size_;
  uint32_t field_ids_off_;

  uint32_t method_ids_size_;
  uint32_t method_ids_off_;

  uint32_t class_defs_size_;
  uint32_t class_defs_off_;

  uint32_t data_size_;
  uint32_t data_off_;

};

} // Namespace DEX
} // Namespace LIEF

#endif
