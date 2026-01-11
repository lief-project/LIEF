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
#include <jni.h>
#include <jni_bind.h>
#include <spdlog/logger.h>

#include "jni/log.hpp"
#include "jni/ghidra_logger_sink.hpp"

#include "jni/lief/dwarf/Editor.hpp"
#include "jni/lief/generic/jni.hpp"

#include "jni/lief/elf/jni.hpp"
#include "jni/lief/pe/jni.hpp"
#include "jni/lief/macho/jni.hpp"

#include "jni/lief/Utils.hpp"

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
  static auto jvm = std::make_unique<jni::JvmRef<jni::kDefaultJvm>>(vm);
  LIEF::logging::named::set_logger(GHIDRA_LIEF_LOGGER_NAME,
    spdlog::ghidra_logger_mt(GHIDRA_LIEF_LOGGER_NAME, GHIDRA_LIEF_LOGGER_NAME)
  );

  LIEF::logging::named::set_level(
    GHIDRA_LIEF_LOGGER_NAME,
    getenv("LIEF_JNI_DEBUG") != nullptr ? LIEF::logging::LEVEL::DEBUG :
                                          LIEF::logging::LEVEL::INFO
  );

  JNIEnv* env = nullptr;
  if (int ret = vm->GetEnv((void**)&env, JNI_VERSION_1_6); ret == JNI_EDETACHED) {
    if (vm->AttachCurrentThread((void**)env, /*args=*/nullptr) != JNI_OK) {
      return JNI_ERR;
    }
  }
  lief_jni::Utils::register_natives(env);
  lief_jni::dwarf::Editor::register_natives(env);
  lief_jni::generic::register_natives(env);
  lief_jni::elf::register_natives(env);
  lief_jni::pe::register_natives(env);
  lief_jni::macho::register_natives(env);


  return JNI_VERSION_1_6;
}
