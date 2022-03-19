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
#ifndef LIEF_ART_FILE_H_
#define LIEF_ART_FILE_H_
#include <iostream>

#include "LIEF/ART/Header.hpp"
#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace ART {
class Parser;

class LIEF_API File : public Object {
  friend class Parser;

 public:
  File& operator=(const File& copy) = delete;
  File(const File& copy) = delete;

  const Header& header() const;
  Header& header();

  void accept(Visitor& visitor) const override;

  bool operator==(const File& rhs) const;
  bool operator!=(const File& rhs) const;

  ~File() override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os,
                                           const File& art_file);

 private:
  File();

  Header header_;
};

}  // namespace ART
}  // namespace LIEF

#endif
