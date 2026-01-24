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

#include "jni/lief/pe/aarch64/UnpackedFunction.hpp"
#include "jni/log.hpp"
#include "jni/jni_utils.hpp"

namespace lief_jni::pe::aarch64 {

int UnpackedFunction::register_natives(JNIEnv* env) {
  static const std::array NATIVE_METHODS {
    make(
      "isExtended",
      "()Z",
      jni_is_extended
    ),
    make(
      "getXdataRVA",
      "()I",
      jni_get_xdata_rva
    ),
    make(
      "getUnwindCodeOffset",
      "()J",
      jni_get_unwind_code_offset
    ),
    make(
      "getEpilogScopesOffset",
      "()J",
      jni_get_epilog_scopes_offset
    ),
    make(
      "getNbEpilogScopes",
      "()J",
      jni_get_nb_epilog_scopes
    ),
    make(
      "getExceptionHandlerOffset",
      "()J",
      jni_get_exception_handler_offset
    ),
    make(
      "getUnwindCode",
      "()[B",
      jni_get_unwind_code
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

  return JNI_OK;
}

}
