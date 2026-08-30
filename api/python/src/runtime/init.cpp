/* Copyright 2017 - 2026 R. Thomas
 * Copyright 2017 - 2026 Quarkslab
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
#include "runtime/init.hpp"
#include "runtime/pyRuntime.hpp"
#include "runtime/objects/linux/init.hpp"
#include "runtime/objects/windows/init.hpp"
#include "runtime/objects/android/init.hpp"
#include "runtime/objects/osx/init.hpp"

#include "LIEF/runtime/utils.hpp"
#include "LIEF/config.h"

namespace LIEF::runtime {
class Process;
class Module;
class Memory;
class MemoryLayout;
class Host;
}

namespace LIEF::runtime::py {
void init_disassembler(nb::module_& m);
void init_assembler(nb::module_& m);

void init(nb::module_& m) {
  nb::module_ runtime_mod = m.def_submodule("runtime");

  nb::enum_<ARCH>(runtime_mod, "ARCH")
    .value("NONE", ARCH::NONE)
    .value("X86_64", ARCH::X86_64)
    .value("ARM64", ARCH::ARM64)
    .value("RISCV64", ARCH::RISCV64)
  ;

  nb::enum_<PLATFORMS>(runtime_mod, "PLATFORMS")
    .value("NONE", PLATFORMS::NONE)
    .value("LINUX", PLATFORMS::LINUX)
    .value("WINDOWS", PLATFORMS::WINDOWS)
    .value("ANDROID", PLATFORMS::ANDROID_)
    .value("OSX", PLATFORMS::OSX)
    .value("IOS", PLATFORMS::IOS)
  ;

  runtime_mod.attr("enabled") = (bool)lief_runtime_support;
  runtime_mod.attr("platform") = platform();
  runtime_mod.attr("arch") = arch();

  create<LIEF::runtime::Host>(runtime_mod);
  create<LIEF::runtime::Process>(runtime_mod);
  create<LIEF::runtime::Module>(runtime_mod);
  create<LIEF::runtime::Memory>(runtime_mod);
  create<LIEF::runtime::MemoryLayout>(runtime_mod);
  init_disassembler(runtime_mod);
  init_assembler(runtime_mod);

  Linux::py::init(runtime_mod);
  android::py::init(runtime_mod);
  windows::py::init(runtime_mod);
  osx::py::init(runtime_mod);
}
}
