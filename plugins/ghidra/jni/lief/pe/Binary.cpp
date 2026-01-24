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

#include "jni/lief/pe/Binary.hpp"
#include "jni/log.hpp"
#include "jni/jni_utils.hpp"

namespace lief_jni::pe {
int Binary::ExceptionsIterator::register_natives(JNIEnv* env) {
  static const std::array NATIVE_METHODS {
    make(
      "hasNext",
      "()Z",
      &jni_has_next
    ),
    make(
      "next",
      "()Llief/pe/ExceptionInfo;",
      &jni_next
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

int Binary::register_natives(JNIEnv* env) {
  static const std::array NATIVE_METHODS {
    make(
      "parse",
      "(Ljava/lang/String;)Llief/pe/Binary;",
      jni_parse
    ),
    make(
      "getLoadConfiguration",
      "()Ljava/util/Optional;",
      jni_get_load_configuration
    ),
    make(
      "getLoadConfigurationDir",
      "()Ljava/util/Optional;",
      jni_get_load_configuration_dir
    ),
    make(
      "getExceptions",
      "()Llief/pe/Binary$ExceptionsIterator;",
      jni_get_exceptions
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

  LoadConfiguration::register_natives(env);
  DataDirectory::register_natives(env);
  ExceptionsIterator::register_natives(env);
  ExceptionInfo::register_natives(env);

  return JNI_OK;
}

}
