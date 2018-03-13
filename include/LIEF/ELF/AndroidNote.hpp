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

namespace LIEF {
namespace ELF {

class Parser;
class Builder;
class Binary;

//! Class representing the ".note.android.ident" section
//!
//! @See: https://android.googlesource.com/platform/ndk/+/ndk-release-r16/sources/crt/crtbrand.S#39
class LIEF_API AndroidNote : public Note {

  friend class Parser;
  friend class Builder;
  friend class Binary;
  public:
  static constexpr const char NAME[] = "Android";

  public:
  using Note::Note;


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
};


} // namepsace ELF
} // namespace LIEF

#endif
