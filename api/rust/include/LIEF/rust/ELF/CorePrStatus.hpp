/* Copyright 2024 - 2026 R. Thomas
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
#pragma once
#include "LIEF/rust/ELF/Note.hpp"
#include "LIEF/rust/error.hpp"
#include "LIEF/ELF/NoteDetails/core/CorePrStatus.hpp"

class ELF_CorePrStatus_Status {
  public:
  // siginfo_t
  int32_t signo = 0;
  int32_t code = 0;
  int32_t err = 0;

  uint16_t cursig = 0;
  uint16_t reserved = 0;

  uint64_t sigpend = 0;
  uint64_t sighold = 0;

  int32_t pid = 0;
  int32_t ppid = 0;
  int32_t pgrp = 0;
  int32_t sid = 0;

  uint64_t utime_sec = 0;
  uint64_t utime_usec = 0;

  uint64_t stime_sec = 0;
  uint64_t stime_usec = 0;

  uint64_t cutime_sec = 0;
  uint64_t cutime_usec = 0;

  uint64_t cstime_sec = 0;
  uint64_t cstime_usec = 0;
};

class ELF_CorePrStatus : public ELF_Note {
  public:
  using lief_t = LIEF::ELF::CorePrStatus;
  ELF_CorePrStatus(const lief_t& impl) :
    ELF_Note(static_cast<const ELF_Note::lief_t&>(impl)) {}

  auto architecture() const {
    return (uint32_t)impl().architecture();
  }

  auto status() const {
    const lief_t::pr_status_t& S = impl().status();
    return std::make_unique<ELF_CorePrStatus_Status>(ELF_CorePrStatus_Status{
        .signo = S.info.signo,
        .code = S.info.code,
        .err = S.info.err,

        .cursig = S.cursig,
        .reserved = S.reserved,

        .sigpend = S.sigpend,
        .sighold = S.sighold,

        .pid = S.pid,
        .ppid = S.ppid,
        .pgrp = S.pgrp,
        .sid = S.sid,

        .utime_sec = S.utime.sec,
        .utime_usec = S.utime.usec,

        .stime_sec = S.stime.sec,
        .stime_usec = S.stime.usec,

        .cutime_sec = S.cutime.sec,
        .cutime_usec = S.cutime.usec,

        .cstime_sec = S.cstime.sec,
        .cstime_usec = S.cstime.usec,
    });
  }

  uint64_t pc(uint32_t& err) const {
    return details::make_error(impl().pc(), err);
  }

  uint64_t sp(uint32_t& err) const {
    return details::make_error(impl().sp(), err);
  }

  uint64_t return_value(uint32_t& err) const {
    return details::make_error(impl().return_value(), err);
  }

  auto register_values() const {
    return impl().register_values();
  }

  static bool classof(const ELF_Note& note) {
    return lief_t::classof(&note.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
};
