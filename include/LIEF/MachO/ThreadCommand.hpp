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
#ifndef LIEF_MACHO_THREAD_COMMAND_H_
#define LIEF_MACHO_THREAD_COMMAND_H_
#include <iostream>
#include <vector>

#include "LIEF/MachO/LoadCommand.hpp"
#include "LIEF/types.hpp"
#include "LIEF/visibility.h"

namespace LIEF {
namespace MachO {

class BinaryParser;

namespace details {
struct thread_command;
}

//! Class that represents the LC_THREAD / LC_UNIXTHREAD commands and that
//! can be used to get the binary entrypoint when the LC_MAIN (MainCommand) is
//! not present
//!
//! Generally speaking, this command aims at defining the original state
//! of the main thread which includes the registers' values
class LIEF_API ThreadCommand : public LoadCommand {
  friend class BinaryParser;

 public:
  ThreadCommand();
  ThreadCommand(const details::thread_command& cmd,
                CPU_TYPES arch = CPU_TYPES::CPU_TYPE_ANY);
  ThreadCommand(uint32_t flavor, uint32_t count,
                CPU_TYPES arch = CPU_TYPES::CPU_TYPE_ANY);

  ThreadCommand& operator=(const ThreadCommand& copy);
  ThreadCommand(const ThreadCommand& copy);

  ThreadCommand* clone() const override;

  virtual ~ThreadCommand();

  //! Integer that defines a special *flavor* for the thread.
  //!
  //! The meaning of this value depends on the architecture(). The list of
  //! the values can be found in the XNU kernel files:
  //! - xnu/osfmk/mach/arm/thread_status.h  for the ARM/AArch64 architectures
  //! - xnu/osfmk/mach/i386/thread_status.h for the x86/x86-64 architectures
  uint32_t flavor() const;

  //! Size of the thread state data with 32-bits alignment.
  //!
  //! This value should match state().size()
  uint32_t count() const;

  //! The CPU architecture that is targeted by this ThreadCommand
  CPU_TYPES architecture() const;

  //! The actual thread state as a vector of bytes. Depending on the
  //! architecture(), these data can be casted into x86_thread_state_t,
  //! x86_thread_state64_t, ...
  const std::vector<uint8_t>& state() const;
  std::vector<uint8_t>& state();

  //! Return the initial Program Counter regardless of the underlying
  //! architecture. This value, when non null, can be used to determine the
  //! binary's entrypoint.
  //!
  //! Underneath, it works by looking for the PC register value in the state()
  //! data
  uint64_t pc() const;

  void state(const std::vector<uint8_t>& state);
  void flavor(uint32_t flavor);
  void count(uint32_t count);
  void architecture(CPU_TYPES arch);

  bool operator==(const ThreadCommand& rhs) const;
  bool operator!=(const ThreadCommand& rhs) const;

  void accept(Visitor& visitor) const override;

  std::ostream& print(std::ostream& os) const override;

  static bool classof(const LoadCommand* cmd);

 private:
  uint32_t flavor_;
  uint32_t count_;
  CPU_TYPES architecture_;
  std::vector<uint8_t> state_;
};

}  // namespace MachO
}  // namespace LIEF
#endif
