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
#ifndef LIEF_ELF_ANDROID_NOTE_H_
#define LIEF_ELF_ANDROID_NOTE_H_

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

//! Class representing the ".note.android.ident" section
//!
//! @See: https://android.googlesource.com/platform/ndk/+/ndk-release-r16/sources/crt/crtbrand.S#39
class LIEF_API AndroidNote : public NoteDetails {

  friend class Parser;
  friend class Builder;
  friend class Binary;

  public:
  static constexpr const char NAME[] = "Android";

  static constexpr size_t sdk_version_offset      = 0;
  static constexpr size_t sdk_version_size        = sizeof(uint32_t);

  static constexpr size_t ndk_version_offset      = sdk_version_offset + sdk_version_size;
  static constexpr size_t ndk_version_size        = 64 * sizeof(char);

  static constexpr size_t ndk_build_number_offset = ndk_version_offset + ndk_version_size;
  static constexpr size_t ndk_build_number_size   = 64 * sizeof(char);

  static AndroidNote make(Note& note);

  public:
  using NoteDetails::NoteDetails;
  using description_t = typename Note::description_t;

  virtual AndroidNote* clone(void) const override;

  //! Target SDK version
  uint32_t sdk_version(void) const;

  //! NDK version used
  std::string ndk_version(void) const;

  //! NDK build number
  std::string ndk_build_number(void) const;

  void sdk_version(uint32_t version);
  void ndk_version(const std::string& ndk_version);
  void ndk_build_number(const std::string& ndk_build_number);

  bool operator==(const AndroidNote& rhs) const;
  bool operator!=(const AndroidNote& rhs) const;

  virtual void dump(std::ostream& os) const override;

  virtual void accept(Visitor& visitor) const override;

  virtual ~AndroidNote(void);

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const AndroidNote& note);

  protected:
  virtual void parse(void) override;
  virtual void build(void) override;

  private:
  AndroidNote(Note& note);

  uint32_t sdk_version_;
  std::string ndk_version_;
  std::string ndk_build_number_;
};


} // namepsace ELF
} // namespace LIEF

#endif
