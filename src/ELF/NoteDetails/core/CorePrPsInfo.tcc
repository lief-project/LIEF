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

#include "LIEF/ELF/NoteDetails/core/CorePrPsInfo.hpp"
#include "LIEF/ELF/Note.hpp"
#include "LIEF/ELF/Binary.hpp"

namespace LIEF {
namespace ELF {

template <typename ELF_T>
void CorePrPsInfo::parse_() {
  using Elf_Prpsinfo  = typename ELF_T::Elf_Prpsinfo;

  const Note::description_t& desc = description();

  if (desc.size() < sizeof(Elf_Prpsinfo)) {
    return;
  }

  const auto* info = reinterpret_cast<const Elf_Prpsinfo*>(desc.data());

  // parse info structure
  file_name_ = std::string(info->pr_fname, sizeof(info->pr_fname)).c_str();
  flags_     = info->pr_flag;
  uid_       = info->pr_uid;
  gid_       = info->pr_gid;
  pid_       = info->pr_pid;
  ppid_      = info->pr_ppid;
  pgrp_      = info->pr_pgrp;
  sid_       = info->pr_sid;
}

template <typename ELF_T>
void CorePrPsInfo::build_() {
  using Elf_Prpsinfo  = typename ELF_T::Elf_Prpsinfo;
  Note::description_t& desc = description();
  constexpr size_t desc_size = sizeof(Elf_Prpsinfo);
  if (desc.size() < desc_size) {
    desc.resize(desc_size);
  }

  auto* info = reinterpret_cast<Elf_Prpsinfo*>(desc.data());
  // update info structure
  const size_t fname_size = sizeof(info->pr_fname) - 1;

  std::string fname = file_name_;
  fname.resize(fname_size, 0);

  std::move(
      std::begin(file_name_),
      std::end(file_name_),
      info->pr_fname);

  info->pr_flag = flags_;
  info->pr_uid  = uid_;
  info->pr_gid  = gid_;
  info->pr_pid  = pid_;
  info->pr_ppid = ppid_;
  info->pr_pgrp = pgrp_;
  info->pr_sid  = sid_;
}

} // namespace ELF
} // namespace LIEF
