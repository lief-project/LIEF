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
#ifndef LIEF_ELF_NOTE_DETAILS_ABI_H_
#define LIEF_ELF_NOTE_DETAILS_ABI_H_

#include <vector>
#include <iostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"
#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/NoteDetails.hpp"

namespace LIEF {
namespace ELF {

class Parser;
class Builder;
class Binary;

//! Class representing the ``.note.android.ident`` section
//!
//! @see: https://android.googlesource.com/platform/ndk/+/ndk-release-r16/sources/crt/crtbrand.S#39
class LIEF_API NoteAbi : public NoteDetails {

  friend class Parser;
  friend class Builder;
  friend class Binary;

  public:

  //! Version type: (Major, Minor, Patch)
  using version_t = std::array<uint32_t, 3>;

  static constexpr size_t abi_offset      = 0;
  static constexpr size_t abi_size        = sizeof(uint32_t);

  static constexpr size_t version_offset  = abi_offset + abi_size;
  static constexpr size_t version_size    = 3 * sizeof(uint32_t);

  static NoteAbi make(Note& note);

  NoteAbi* clone() const override;

  public:
  using NoteDetails::NoteDetails;
  using description_t = typename Note::description_t;

  //! @brief Return the target version as ``<Major, Minor, Patch>``.
  version_t version() const;

  //! @brief Return the target ABI. Require a NT_GNU_ABI_TAG type
  NOTE_ABIS abi() const;

  bool operator==(const NoteAbi& rhs) const;
  bool operator!=(const NoteAbi& rhs) const;

  void dump(std::ostream& os) const override;

  void accept(Visitor& visitor) const override;

  virtual ~NoteAbi();

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const NoteAbi& note);

  protected:
  void parse() override;

  private:
  NoteAbi(Note& note);

  version_t version_;
  NOTE_ABIS abi_;

};


} // namepsace ELF
} // namespace LIEF

#endif
