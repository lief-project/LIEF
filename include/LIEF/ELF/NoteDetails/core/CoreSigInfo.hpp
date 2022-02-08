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
#ifndef LIEF_ELF_CORE_SIGINFO_H_
#define LIEF_ELF_CORE_SIGINFO_H_

#include <vector>
#include <iostream>
#include <map>
#include <utility>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/ELF/NoteDetails.hpp"

namespace LIEF {
namespace ELF {

class Note;
class Parser;
class Builder;
class Binary;

//! Class representing core siginfo object
class LIEF_API CoreSigInfo : public NoteDetails {

  public:
  using NoteDetails::NoteDetails;

  public:
  static CoreSigInfo make(Note& note);

  CoreSigInfo* clone() const override;

  //! Signal number.
  int32_t signo() const;

  //! Signal code.
  int32_t sigcode() const;

  //! If non-zero, an errno value associated with this signal.
  int32_t sigerrno() const;

  void signo(int32_t signo);
  void sigcode(int32_t sigcode);
  void sigerrno(int32_t sigerrno);

  bool operator==(const CoreSigInfo& rhs) const;
  bool operator!=(const CoreSigInfo& rhs) const;

  void dump(std::ostream& os) const override;

  void accept(Visitor& visitor) const override;

  virtual ~CoreSigInfo();

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const CoreSigInfo& note);

  protected:
  void parse() override;
  void build() override;

  private:
  CoreSigInfo(Note& note);
  struct siginfo_t {
    int32_t si_signo;
    int32_t si_code;
    int32_t si_errno;
  };

  siginfo_t siginfo_;
};


} // namepsace ELF
} // namespace LIEF

#endif
