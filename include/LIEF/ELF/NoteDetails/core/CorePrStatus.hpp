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
#ifndef LIEF_ELF_CORE_PRSTATUS_H_
#define LIEF_ELF_CORE_PRSTATUS_H_

#include <vector>
#include <iostream>
#include <map>
#include <utility>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/ELF/NoteDetails.hpp"

namespace LIEF {
namespace ELF {

class Parser;
class Builder;
class Binary;

//! Class representing core PrPsInfo object
class LIEF_API CorePrStatus : public NoteDetails {

  public:
  using NoteDetails::NoteDetails;
  struct siginfo_t {
    int32_t si_signo;
    int32_t si_code;
    int32_t si_errno;
  };

  struct timeval_t {
    uint64_t sec;
    uint64_t usec;
  };


  enum class REGISTERS  {
    UNKNOWN,

    // x86
    // ===
    X86_START,
      X86_EBX, X86_ECX, X86_EDX, X86_ESI, X86_EDI, X86_EBP, X86_EAX,
      X86_DS, X86_ES, X86_FS, X86_GS, X86__, X86_EIP, X86_CS, X86_EFLAGS, X86_ESP, X86_SS,
    X86_END,

    // x86-64
    // ======
    X86_64_START,
      X86_64_R15, X86_64_R14, X86_64_R13, X86_64_R12, X86_64_RBP, X86_64_RBX, X86_64_R11, X86_64_R10,
      X86_64_R9, X86_64_R8, X86_64_RAX, X86_64_RCX, X86_64_RDX, X86_64_RSI, X86_64_RDI, X86_64__,
      X86_64_RIP, X86_64_CS, X86_64_EFLAGS, X86_64_RSP, X86_64_SS,
    X86_64_END,

    // ARM
    // ===
    ARM_START,
      ARM_R0, ARM_R1, ARM_R2,  ARM_R3,  ARM_R4,  ARM_R5,  ARM_R6,  ARM_R7,
      ARM_R8, ARM_R9, ARM_R10, ARM_R11, ARM_R12, ARM_R13, ARM_R14, ARM_R15,
      ARM_CPSR,
    ARM_END,

    // AArch64
    // =======
    AARCH64_START,
      AARCH64_X0,  AARCH64_X1,  AARCH64_X2,  AARCH64_X3,  AARCH64_X4,  AARCH64_X5,  AARCH64_X6,  AARCH64_X7,
      AARCH64_X8,  AARCH64_X9,  AARCH64_X10, AARCH64_X11, AARCH64_X12, AARCH64_X13, AARCH64_X14, AARCH64_X15,
      AARCH64_X16, AARCH64_X17, AARCH64_X18, AARCH64_X19, AARCH64_X20, AARCH64_X21, AARCH64_X22, AARCH64_X23,
      AARCH64_X24, AARCH64_X25, AARCH64_X26, AARCH64_X27, AARCH64_X28, AARCH64_X29, AARCH64_X30, AARCH64_X31,
      AARCH64_PC, AARCH64__,
    AARCH64_END,
  };
  using reg_context_t = std::map<REGISTERS, uint64_t>;

  public:
  static CorePrStatus make(Note& note);

  CorePrStatus* clone() const override;

  //! Info associated with the signal
  const siginfo_t& siginfo() const;

  //! Current Signal
  uint16_t current_sig() const;

  //! Set of pending signals
  uint64_t sigpend() const;

  //! Set of held signals
  uint64_t sighold() const;

  //! Process ID
  int32_t pid() const;

  //! Process parent ID
  int32_t ppid() const;

  //! Process group ID
  int32_t pgrp() const;

  //! Process session ID
  int32_t sid() const;

  //! User time
  timeval_t utime() const;

  //! System time
  timeval_t stime() const;

  //! Cumulative user time
  timeval_t cutime() const;

  //! Cumulative system time
  timeval_t cstime() const;

  //! GP registers state
  const reg_context_t& reg_context() const;

  //! Return the program counter
  uint64_t pc() const;

  //! Return the stack pointer
  uint64_t sp() const;

  //! Get register value. If ``error`` is set,
  //! this function and the register exists, the function set the boolean value to ``false``
  //! Otherwise it set the value to ``true``
  uint64_t get(REGISTERS reg, bool* error = nullptr) const;

  //! Check if the given register is present in the info
  bool has(REGISTERS reg) const;

  void siginfo(const siginfo_t& siginfo);
  void current_sig(uint16_t current_sig);

  void sigpend(uint64_t sigpend);
  void sighold(uint64_t sighold);

  void pid(int32_t pid);
  void ppid(int32_t ppid);
  void pgrp(int32_t pgrp);
  void sid(int32_t sid);

  void utime(timeval_t utime);
  void stime(timeval_t stime);
  void cutime(timeval_t cutime);
  void cstime(timeval_t cstime);

  void reg_context(const reg_context_t& ctx);

  bool set(REGISTERS reg, uint64_t value);

  bool operator==(const CorePrStatus& rhs) const;
  bool operator!=(const CorePrStatus& rhs) const;

  uint64_t& operator[](REGISTERS reg);

  void dump(std::ostream& os) const override;
  static std::ostream& dump(std::ostream& os, const timeval_t& time);
  static std::ostream& dump(std::ostream& os, const siginfo_t& siginfo);
  static std::ostream& dump(std::ostream& os, const reg_context_t& ctx);

  void accept(Visitor& visitor) const override;

  virtual ~CorePrStatus();

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const CorePrStatus& note);

  protected:
  template <typename ELF_T>
  LIEF_LOCAL void parse_();

  template <typename ELF_T>
  LIEF_LOCAL void build_();

  void parse() override;
  void build() override;

  private:
  CorePrStatus(Note& note);

  std::pair<size_t, size_t> reg_enum_range() const;

  siginfo_t siginfo_;
  uint16_t  cursig_;

  uint64_t sigpend_;
  uint64_t sighold_;

  int32_t pid_;
  int32_t ppid_;
  int32_t pgrp_;
  int32_t sid_;

  timeval_t utime_;
  timeval_t stime_;
  timeval_t cutime_;
  timeval_t cstime_;

  reg_context_t ctx_;
};


LIEF_API const char* to_string(CorePrStatus::REGISTERS e);

} // namepsace ELF
} // namespace LIEF

#endif
