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

#include "jni/lief/dwarf/editor/FunctionType.hpp"
#include "jni/log.hpp"
#include "jni/jni_utils.hpp"

namespace lief_jni::dwarf::editor {

int FunctionType::Parameter::register_natives(JNIEnv* env) {
  static const std::array NATIVE_METHODS {
    make_destroy(
      (void*)&jni_destroy
    ),
  };

  env->RegisterNatives(
    jni::StaticRef<kClass>{}.GetJClass(),
    NATIVE_METHODS.data(), NATIVE_METHODS.size()
  );

  GHIDRA_DEBUG("'{}' registered", kClass.name_);

  return JNI_OK;
}

int FunctionType::register_natives(JNIEnv* env) {
  static const std::array NATIVE_METHODS {
    make(
      "setReturnType",
      "(Llief/dwarf/editor/Type;)Llief/dwarf/editor/FunctionType;",
      &jni_set_return_type
    ),
    make(
      "addParameter",
      "(Llief/dwarf/editor/Type;)Llief/dwarf/editor/FunctionType$Parameter;",
      &jni_add_parameter
    ),
    make_destroy(
      (void*)&jni_destroy
    ),
  };

  env->RegisterNatives(
    jni::StaticRef<kClass>{}.GetJClass(),
    NATIVE_METHODS.data(), NATIVE_METHODS.size()
  );

  GHIDRA_DEBUG("'{}' registered", kClass.name_);

  Parameter::register_natives(env);

  return JNI_OK;
}

}
