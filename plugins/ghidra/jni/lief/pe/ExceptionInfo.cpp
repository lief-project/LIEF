/* Copyright 2022 - 2026 R. Thomas
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
#include <array>

#include "jni/lief/pe/ExceptionInfo.hpp"
#include "jni/lief/pe/RuntimeFunctionAArch64.hpp"
#include "jni/lief/pe/aarch64/PackedFunction.hpp"
#include "jni/lief/pe/aarch64/UnpackedFunction.hpp"
#include "jni/lief/pe/RuntimeFunctionX64.hpp"

#include "jni/log.hpp"
#include "jni/jni_utils.hpp"

#include "LIEF/PE/exceptions_info/RuntimeFunctionAArch64.hpp"
#include "LIEF/PE/exceptions_info/RuntimeFunctionX64.hpp"
#include "LIEF/PE/exceptions_info/AArch64/PackedFunction.hpp"
#include "LIEF/PE/exceptions_info/AArch64/UnpackedFunction.hpp"

namespace lief_jni::pe {

int ExceptionInfo::register_natives(JNIEnv* env) {
  static const std::array NATIVE_METHODS {
    make(
      "getRVA",
      "()I",
      jni_get_rva
    ),

    make(
      "getOffset",
      "()I",
      jni_get_offset
    ),

    make_destroy(
      &jni_destroy
    ),
  };

  env->RegisterNatives(
    jni::StaticRef<kClass>{}.GetJClass(),
    NATIVE_METHODS.data(), NATIVE_METHODS.size()
  );

  GHIDRA_DEBUG("'{}' registered", kClass.name_);

  RuntimeFunctionAArch64::register_natives(env);
  RuntimeFunctionX64::register_natives(env);

  return JNI_OK;
}

jobject ExceptionInfo::create_impl(lief_t& impl) {
  if (auto* arm64 = impl.as<LIEF::PE::RuntimeFunctionAArch64>()) {
    if (auto* unpacked = arm64->as<LIEF::PE::unwind_aarch64::UnpackedFunction>()) {
      return aarch64::UnpackedFunction::create<aarch64::UnpackedFunction>(*arm64);
    }

    if (auto* packed = arm64->as<LIEF::PE::unwind_aarch64::PackedFunction>()) {
      return aarch64::PackedFunction::create<aarch64::PackedFunction>(*arm64);
    }

    return nullptr;
  }

  if (auto* x64 = impl.as<LIEF::PE::RuntimeFunctionX64>()) {
    return RuntimeFunctionX64::create<RuntimeFunctionX64>(*x64);
  }

  return nullptr;
}


}
