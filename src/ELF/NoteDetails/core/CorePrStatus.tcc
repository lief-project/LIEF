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
#include <algorithm>

#include "LIEF/exception.hpp"
#include "LIEF/utils.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"
#include "LIEF/iostream.hpp"

#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/NoteDetails/core/CorePrStatus.hpp"

namespace LIEF {
namespace ELF {

template <typename ELF_T>
void CorePrStatus::parse_(void) {
  using Elf_Prstatus  = typename ELF_T::Elf_Prstatus;
  using uint__        = typename ELF_T::uint;

  const Note::description_t& description = this->description();
  if (description.size() < sizeof(Elf_Prstatus)) {
    return;
  }
  auto&& status = reinterpret_cast<const Elf_Prstatus*>(description.data());

  this->siginfo_ = status->pr_info;
  this->cursig_  = status->pr_cursig;

  this->sigpend_ = status->pr_sigpend;
  this->sighold_ = status->pr_sighold;

  this->pid_  = status->pr_pid;
  this->ppid_ = status->pr_ppid;
  this->pgrp_ = status->pr_pgrp;
  this->sid_  = status->pr_sid;

  this->utime_.tv_sec   = status->pr_utime.tv_sec;
  this->utime_.tv_usec  = status->pr_utime.tv_usec;

  this->stime_.tv_sec   = status->pr_stime.tv_sec;
  this->stime_.tv_usec  = status->pr_stime.tv_usec;

  this->cutime_.tv_sec  = status->pr_cutime.tv_sec;
  this->cutime_.tv_usec = status->pr_cutime.tv_usec;

  this->cstime_.tv_sec  = status->pr_cstime.tv_sec;
  this->cstime_.tv_usec = status->pr_cstime.tv_usec;

  size_t enum_start = 0;
  size_t enum_end   = 0;
  std::tie(enum_start, enum_end) = this->reg_enum_range();

  const VectorStream& stream(description);
  stream.setpos(sizeof(Elf_Prstatus));

  for (size_t i = enum_start; i < enum_end; ++i) {
    if (not stream.can_read<uint__>()) {
      break;
    }
    this->ctx_[static_cast<REGISTERS>(i)] = stream.read<uint__>();
  }



}

template <typename ELF_T>
void CorePrStatus::build_(void) {
  using Elf_Prstatus  = typename ELF_T::Elf_Prstatus;
  using uint__        = typename ELF_T::uint;

  Note::description_t& description = this->description();
  Elf_Prstatus status;

  status.pr_info.si_signo  = static_cast<int32_t>(this->siginfo_.si_signo);
  status.pr_info.si_code   = static_cast<int32_t>(this->siginfo_.si_code);
  status.pr_info.si_errno  = static_cast<int32_t>(this->siginfo_.si_errno);

  status.pr_cursig         = static_cast<uint16_t>(this->cursig_);
  status.reserved          = static_cast<uint16_t>(0xFE19);

  status.pr_sigpend        = static_cast<uint__>(this->sigpend_);
  status.pr_sighold        = static_cast<uint__>(this->sighold_);

  status.pr_pid            = static_cast<int32_t>(this->pid_);
  status.pr_ppid           = static_cast<int32_t>(this->ppid_);
  status.pr_pgrp           = static_cast<int32_t>(this->pgrp_);
  status.pr_sid            = static_cast<int32_t>(this->sid_);

  status.pr_utime.tv_sec   = static_cast<uint__>(this->utime_.tv_sec);
  status.pr_utime.tv_usec  = static_cast<uint__>(this->utime_.tv_usec);

  status.pr_stime.tv_sec   = static_cast<uint__>(this->stime_.tv_sec);
  status.pr_stime.tv_usec  = static_cast<uint__>(this->stime_.tv_usec);

  status.pr_cutime.tv_sec  = static_cast<uint__>(this->cutime_.tv_sec);
  status.pr_cutime.tv_usec = static_cast<uint__>(this->cutime_.tv_usec);

  status.pr_cstime.tv_sec  = static_cast<uint__>(this->cstime_.tv_sec);
  status.pr_cstime.tv_usec = static_cast<uint__>(this->cstime_.tv_usec);

  vector_iostream raw_output;
  size_t desc_part_size = sizeof(Elf_Prstatus);
  raw_output.reserve(desc_part_size);
  raw_output.write(reinterpret_cast<const uint8_t*>(&status), sizeof(Elf_Prstatus));

  size_t enum_start = 0;
  size_t enum_end = 0;
  std::tie(enum_start, enum_end) = this->reg_enum_range();

  for (size_t i = enum_start; i < enum_end; ++i) {
    REGISTERS reg = static_cast<REGISTERS>(i);
    auto val = static_cast<uint__>(this->get(reg));
    raw_output.write_conv(val);
  }

  std::vector<uint8_t> raw = raw_output.raw();
  std::copy(std::begin(raw), std::end(raw),
      std::begin(description));

}

} // namespace ELF
} // namespace LIEF
