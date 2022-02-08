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
void CorePrStatus::parse_() {
  using Elf_Prstatus  = typename ELF_T::Elf_Prstatus;
  using uint__        = typename ELF_T::uint;

  const Note::description_t& desc = description();
  if (desc.size() < sizeof(Elf_Prstatus)) {
    return;
  }
  const auto* status = reinterpret_cast<const Elf_Prstatus*>(desc.data());

  siginfo_.si_signo = status->pr_info.si_signo;
  siginfo_.si_errno = status->pr_info.si_errno;
  siginfo_.si_code  = status->pr_info.si_code;

  cursig_  = status->pr_cursig;

  sigpend_ = status->pr_sigpend;
  sighold_ = status->pr_sighold;

  pid_  = status->pr_pid;
  ppid_ = status->pr_ppid;
  pgrp_ = status->pr_pgrp;
  sid_  = status->pr_sid;

  utime_.sec   = status->pr_utime.tv_sec;
  utime_.usec  = status->pr_utime.tv_usec;

  stime_.sec   = status->pr_stime.tv_sec;
  stime_.usec  = status->pr_stime.tv_usec;

  cutime_.sec  = status->pr_cutime.tv_sec;
  cutime_.usec = status->pr_cutime.tv_usec;

  cstime_.sec  = status->pr_cstime.tv_sec;
  cstime_.usec = status->pr_cstime.tv_usec;

  size_t enum_start = 0;
  size_t enum_end   = 0;
  std::tie(enum_start, enum_end) = reg_enum_range();

  VectorStream stream(std::move(desc));
  stream.setpos(sizeof(Elf_Prstatus));

  for (size_t i = enum_start; i < enum_end; ++i) {
    auto val = stream.read<uint__>();
    if (!val) {
      break;
    }
    ctx_[static_cast<REGISTERS>(i)] = *val;
  }
}

template <typename ELF_T>
void CorePrStatus::build_() {
  using Elf_Prstatus  = typename ELF_T::Elf_Prstatus;
  using uint__        = typename ELF_T::uint;

  Note::description_t& desc = description();
  Elf_Prstatus status;

  status.pr_info.si_signo  = static_cast<int32_t>(siginfo_.si_signo);
  status.pr_info.si_code   = static_cast<int32_t>(siginfo_.si_code);
  status.pr_info.si_errno  = static_cast<int32_t>(siginfo_.si_errno);

  status.pr_cursig         = static_cast<uint16_t>(cursig_);
  status.reserved          = static_cast<uint16_t>(0xFE19);

  status.pr_sigpend        = static_cast<uint__>(sigpend_);
  status.pr_sighold        = static_cast<uint__>(sighold_);

  status.pr_pid            = static_cast<int32_t>(pid_);
  status.pr_ppid           = static_cast<int32_t>(ppid_);
  status.pr_pgrp           = static_cast<int32_t>(pgrp_);
  status.pr_sid            = static_cast<int32_t>(sid_);

  status.pr_utime.tv_sec   = static_cast<uint__>(utime_.sec);
  status.pr_utime.tv_usec  = static_cast<uint__>(utime_.usec);

  status.pr_stime.tv_sec   = static_cast<uint__>(stime_.sec);
  status.pr_stime.tv_usec  = static_cast<uint__>(stime_.usec);

  status.pr_cutime.tv_sec  = static_cast<uint__>(cutime_.sec);
  status.pr_cutime.tv_usec = static_cast<uint__>(cutime_.usec);

  status.pr_cstime.tv_sec  = static_cast<uint__>(cstime_.sec);
  status.pr_cstime.tv_usec = static_cast<uint__>(cstime_.usec);

  vector_iostream raw_output;
  size_t desc_part_size = sizeof(Elf_Prstatus);
  raw_output.reserve(desc_part_size);
  raw_output.write(reinterpret_cast<const uint8_t*>(&status), sizeof(Elf_Prstatus));

  size_t enum_start = 0;
  size_t enum_end = 0;
  std::tie(enum_start, enum_end) = reg_enum_range();

  for (size_t i = enum_start; i < enum_end; ++i) {
    auto reg = static_cast<REGISTERS>(i);
    auto val = static_cast<uint__>(get(reg));
    raw_output.write_conv(val);
  }

  std::vector<uint8_t> raw = raw_output.raw();
  std::copy(std::begin(raw), std::end(raw),
            std::begin(desc));

}

} // namespace ELF
} // namespace LIEF
