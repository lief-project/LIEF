/* Copyright 2025 - 2026 R. Thomas
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
#include "log.hpp"
#include "binaryninja/analysis/PE/TypeBuilder.hpp"
#include "binaryninja/lief_utils.hpp"

#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/exceptions_info/RuntimeFunctionX64.hpp"
#include "LIEF/PE/exceptions_info/RuntimeFunctionAArch64.hpp"
#include "LIEF/PE/exceptions_info/AArch64/UnpackedFunction.hpp"
#include "LIEF/PE/exceptions_info/AArch64/PackedFunction.hpp"
#include "binaryninja/analysis/PE/analyzers/RuntimeFunctions.hpp"

#include <binaryninja/binaryninjaapi.h>
#include <binaryninja/binaryninjacore.h>

using namespace LIEF;
using namespace BinaryNinja;

namespace analysis_plugin::pe::analyzers {

bool RuntimeFunctions::can_run(BinaryNinja::BinaryView& bv, LIEF::PE::Binary& pe) {
  return !pe.exceptions().empty();
}

void RuntimeFunctions::run() {
  for (const PE::ExceptionInfo& info : pe_.exceptions()) {
    if (const auto* x64 = info.as<PE::RuntimeFunctionX64>()) {
      process(*x64);
    }

    if (const auto* arm64 = info.as<PE::RuntimeFunctionAArch64>()) {
      process(*arm64);
    }
  }
}

void RuntimeFunctions::process(const LIEF::PE::RuntimeFunctionX64& x64) {
  bv_.CreateUserFunction(windows_x64(), translate_addr(get_va(x64.rva_start())));
}

void RuntimeFunctions::process(const LIEF::PE::RuntimeFunctionAArch64& arm64) {
  bv_.CreateUserFunction(windows_arm64(), translate_addr(get_va(arm64.rva_start())));

  if (auto rva = pe_.offset_to_virtual_address(arm64.offset())) {
    uint64_t addr = translate_addr(get_va(*rva));

    if (const auto* packed = arm64.as<PE::unwind_aarch64::PackedFunction>()) {
      // Packed version
      define_struct_at(addr,
          type_builder_.get_or_create("IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY"),
          "__arm64_runtime_function_entry");
    }
    else if (const auto* unpacked = arm64.as<PE::unwind_aarch64::UnpackedFunction>()) {
      // Unpacked version
      define_struct_at(addr,
          type_builder_.get_or_create("IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY"),
          "__arm64_runtime_function_entry");

      uint64_t xdata_addr = translate_addr(get_va(unpacked->xdata_rva()));

      if (unpacked->is_extended()) {
        define_struct_at(xdata_addr,
            type_builder_.get_or_create("IMAGE_ARM64_RUNTIME_FUNCTION_EXTENDED_ENTRY"),
            "__arm64_runtime_function_entry_xdata_extended");
      } else {
        define_struct_at(xdata_addr,
            type_builder_.get_or_create("IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA"),
            "__arm64_runtime_function_entry_xdata");
      }

      if (auto offset = unpacked->epilog_scopes_offset(); offset > 0) {
        define_array_at(xdata_addr + offset,
            type_builder_.u32(), unpacked->epilog_scopes().size(),
            "__arm64_epilog_scopes");
      }

      if (auto offset = unpacked->unwind_code_offset(); offset > 0) {
        define_blob(xdata_addr + unpacked->unwind_code_offset(),
            unpacked->unwind_code().size(), "__arm64_unwind_code");
      }

      if (auto offset = unpacked->exception_handler_offset(); offset > 0) {
        define_type_at(xdata_addr + offset, type_builder_.RVA(),
            "__arm64_runtime_function_exception_handler");
      }
    }
  }
}

}
