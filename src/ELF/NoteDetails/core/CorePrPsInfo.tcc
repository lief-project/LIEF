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

#include "LIEF/ELF/NoteDetails/core/CorePrPsInfo.hpp"
#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/Binary.hpp"

namespace LIEF {
namespace ELF {

template <typename ELF_T>
void CorePrPsInfo::parse_(void) {
  using Elf_Prpsinfo  = typename ELF_T::Elf_Prpsinfo;

  const Note::description_t& description = this->description();

  if (description.size() < sizeof(Elf_Prpsinfo)) {
    return;
  }

  const Elf_Prpsinfo* info = reinterpret_cast<const Elf_Prpsinfo*>(description.data());

  // parse info structure
  this->file_name_ = info->pr_fname;
  this->flags_     = info->pr_flag;
  this->uid_       = info->pr_uid;
  this->gid_       = info->pr_gid;
  this->pid_       = info->pr_pid;
  this->ppid_      = info->pr_ppid;
  this->pgrp_      = info->pr_pgrp;
  this->sid_       = info->pr_sid;
}

template <typename ELF_T>
void CorePrPsInfo::build_(void) {
  using Elf_Prpsinfo  = typename ELF_T::Elf_Prpsinfo;
  Note::description_t& description = this->description();
  constexpr size_t desc_size = sizeof(Elf_Prpsinfo);
  if (description.size() < desc_size) {
    description.resize(desc_size);
  }

  Elf_Prpsinfo* info = reinterpret_cast<Elf_Prpsinfo*>(description.data());
  // update info structure
  const size_t fname_size = sizeof(info->pr_fname) - 1;

  std::string fname = this->file_name_;
  fname.resize(fname_size, 0);

  std::move(
      std::begin(this->file_name_),
      std::end(this->file_name_),
      info->pr_fname);

  info->pr_flag = this->flags_;
  info->pr_uid  = this->uid_;
  info->pr_gid  = this->gid_;
  info->pr_pid  = this->pid_;
  info->pr_ppid = this->ppid_;
  info->pr_pgrp = this->pgrp_;
  info->pr_sid  = this->sid_;
}

} // namespace ELF
} // namespace LIEF
