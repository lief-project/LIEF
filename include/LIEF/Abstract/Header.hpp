/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
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
#ifndef LIEF_ABSTRACT_HEADER_H
#define LIEF_ABSTRACT_HEADER_H

#include <cstdint> // for uint64_t
#include <ostream>
#include <set>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/Abstract/enums.hpp"

namespace LIEF {
class LIEF_API Header : public Object {
  public:
  Header();
  Header(const Header&);
  Header& operator=(const Header&);
  ~Header() override;


  ARCHITECTURES          architecture() const;
  const std::set<MODES>& modes()        const;
  OBJECT_TYPES           object_type()  const;
  uint64_t               entrypoint()   const;
  ENDIANNESS             endianness()   const;


  //! @brief ``true`` if the binary target a ``32-bits`` architecture
  bool is_32() const;

  //! @brief ``true`` if the binary target a ``64-bits`` architecture
  bool is_64() const;

  //! @brief Method so that the ``visitor`` can visit us
  void accept(Visitor& visitor) const override;

  void architecture(ARCHITECTURES arch);
  void modes(const std::set<MODES>& m);
  void object_type(OBJECT_TYPES type);
  void entrypoint(uint64_t entrypoint);
  void endianness(ENDIANNESS endianness);

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const Header& hdr);

  protected:
  ARCHITECTURES   architecture_ = ARCHITECTURES::ARCH_NONE;
  std::set<MODES> modes_;
  OBJECT_TYPES    object_type_ = OBJECT_TYPES::TYPE_NONE;
  uint64_t        entrypoint_ = 0;
  ENDIANNESS      endianness_ = ENDIANNESS::ENDIAN_NONE;
};
}

#endif
